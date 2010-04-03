/*
 *   Lessfs: A data deduplicating filesystem.
 *   Copyright (C) 2008 Mark Ruijter <mruijter@lessfs.com>
 *
 *   This program is free software.
 *   You can redistribute lessfs and/or modify it under the terms of either
 *   (1) the GNU General Public License; either version 3 of the License,
 *   or (at your option) any later version as published by
 *   the Free Software Foundation; or (2) obtain a commercial license
 *   by contacting the Author.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef LFATAL
#include "lib_log.h"
#endif

#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/types.h>
#include <fuse.h>

#include <fcntl.h>
#include <pthread.h>
#include <libgen.h>

#include <tcutil.h>
#include <tcbdb.h>
#include <tchdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <aio.h>
#include "lib_safe.h"
#include "lib_cfg.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "lib_crypto.h"
#include "file_io.h"
#ifdef SHA3
#include "lib_BMW_SHA3api_ref.h"
#endif

extern char *logname;
extern char *function;
extern int debug;
extern int BLKSIZE;
extern int max_threads;
extern BLKDTA **tdta;
extern char *passwd;

extern TCHDB *dbb;
extern TCHDB *dbu;
extern TCHDB *dbp;
extern TCBDB *dbl;
extern TCHDB *dbs;
extern TCHDB *dbdta;
extern TCBDB *dbdirent;
extern TCBDB *freelist;
extern TCMDB *dbcache;
extern TCMDB *dbdtaq;
extern TCMDB *blkcache;
extern TCMDB *dbum;
extern TCMDB *dbbm;
extern int fdbdta;

extern unsigned long long nextoffset;
extern pthread_spinlock_t dbu_spinlock;
extern unsigned int dbu_qcount;

#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }

INUSE *file_get_inuse(unsigned char *stiger)
{
    INUSE *inuse;
    DBT *data;

    FUNC;
    if (NULL == stiger)
        return NULL;
    get_dbu_lock();
    data = search_memhash(dbum, stiger, config->hashlen);
    if ( NULL == data ) {
       data = search_dbdata(dbu, stiger, config->hashlen);
    }
    if (NULL == data) {
        release_dbu_lock();
        LDEBUG("file_get_inuse: nothing found return NULL.");
        return NULL;
    }
    release_dbu_lock();
    inuse=(INUSE *)data->data;
    free(data);
    EFUNC;
    return inuse;
}

void file_update_inuse(unsigned char *stiger, INUSE * inuse)
{
    FUNC;
    LDEBUG
        ("file_update_inuse : update inuse->size = %lu, inuse->inuse = %llu",
         inuse->size, inuse->inuse);
    if (inuse != NULL) {
        get_dbu_lock();
        mbin_write_dbdata(dbum, stiger, config->hashlen, (unsigned char *) inuse,
                         sizeof(INUSE));
        dbu_qcount++;
        release_dbu_lock();
    }
    EFUNC;
    return;
}

unsigned long long round_512(unsigned long long size)
{
    unsigned long long so;
    unsigned long long bytes;

    FUNC;
    so = size / 512;
    if (so != 0) {
        so = so * 512;
    }
    if (so < size) {
        bytes = 512 + so;
    } else
        bytes = so;
    LDEBUG("round_512 : bytes is %llu : size %llu", bytes, size);
    return bytes;
}

void set_new_offset(unsigned long long size)
{
    unsigned long long offset = 0;

    FUNC;
    LDEBUG("oldoffset is %llu : add size %llu", nextoffset, size);
    offset = round_512(size);
    nextoffset = nextoffset + offset;
    LDEBUG("nextoffset is now %llu", nextoffset);
    EFUNC;
    return;
}

unsigned long long get_offset(unsigned long long size)
{
    unsigned long long mbytes;
    unsigned long long offset;
    BDBCUR *cur;
    unsigned long long *dbkey;
    unsigned long long *dboffset;
    int dbsize;
    bool found = 0;

    FUNC;
    mbytes = round_512(size);
    mbytes = mbytes / 512;
    offset = nextoffset;
    LDEBUG("get_offset : search for %llu blocks on the freelist", mbytes);
    cur = tcbdbcurnew(freelist);
    if (tcbdbcurjump(cur, (void *) &mbytes, sizeof(unsigned long long))) {
        if ((dbkey = tcbdbcurkey(cur, &dbsize)) != NULL) {
            if (0 == memcmp(dbkey, &mbytes, sizeof(unsigned long long))) {
                if ((dboffset = tcbdbcurval(cur, &dbsize)) == NULL)
                    die_dataerr("No value for key");
                memcpy(&offset, dboffset, sizeof(unsigned long long));
                found = 1;
                LDEBUG
                    ("get_offset : reclaim %llu blocks on the freelist at offset %llu",
                     mbytes, offset);
                if (!tcbdbcurout(cur)) {
                    die_dataerr
                        ("Failed to delete key, this should never happen!");
                }
                free(dboffset);
            }
            free(dbkey);
        }
    }
    if (!found)
        set_new_offset(size);
    tcbdbcurdel(cur);
    LDEBUG("get_offset returns = %llu", offset);
    EFUNC;
    return (offset);
}

void file_qdta(INOBNO * inobno, unsigned char *stiger, unsigned char *data,
               unsigned long size, unsigned long long offset)
{
    QDTA *dta;

    FUNC;
    dta = (QDTA *) s_malloc(sizeof(QDTA));
    memcpy(&dta->data, data, size);
    dta->size = size;
    dta->offset = offset;
    LDEBUG("file_qdta store block on offset %llu with size %lu",
           dta->offset, size);
    get_moddb_lock();
    loghash("qdta", stiger);
    mbin_write_dbdata(dbdtaq, stiger, config->hashlen, dta, sizeof(QDTA));
    release_moddb_lock();
    free(dta);
    EFUNC;
    return;
}


void add_file_block(BLKDTA * blkdta)
{
    INOBNO inobno;
    DBT *cachedata = NULL;
    INUSE *inuse;

    inobno.inode = blkdta->inode;
    inobno.blocknr = blkdta->blocknr;

    FUNC;
    LDEBUG("add_file_block : inode %llu - %llu", inobno.inode,
           inobno.blocknr);
    if (blkdta->bsize + blkdta->offsetblock < BLKSIZE) {
// Flush the blockcache before overwriting.
        cachedata = try_block_cache(blkdta->inode, blkdta->blocknr, 0);
        if (cachedata)
            DBTfree(cachedata);
        LDEBUG
            ("add_file_block : wrote with add_blk_to_cache  : inode %llu - %llu size %i",
             inobno.inode, inobno.blocknr, blkdta->bsize);
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse, BLKSIZE, 0);
        add_blk_to_cache(blkdta->inode, blkdta->blocknr,
                         blkdta->blockfiller);
        return;
    }
    inuse = file_get_inuse(blkdta->stiger);
    if (inuse == NULL) {
        if (NULL == blkdta->compressed) {
#ifdef LZO
            blkdta->compressed =
                lzo_compress(blkdta->blockfiller, BLKSIZE);
#else
            blkdta->compressed =
                clz_compress(blkdta->blockfiller, BLKSIZE);
#endif
        }
        LDEBUG("Compressed %i bytes to %lu bytes", BLKSIZE,
               blkdta->compressed->size);
        loghash("add_file_block call qdta for hash :", blkdta->stiger);
        inuse = s_malloc(sizeof(INUSE));
        inuse->inuse = 0;
        inuse->offset = get_offset(blkdta->compressed->size);
        LDEBUG("add to offset %llu", inuse->offset);
        inuse->size = blkdta->compressed->size;
        file_qdta(&inobno, blkdta->stiger, blkdta->compressed->data,
                  blkdta->compressed->size, inuse->offset);
        loghash("add_file_block queued with qdta", blkdta->stiger);
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse,
                        blkdta->compressed->size, 0);
    } else {
        update_filesize(blkdta->inode, blkdta->bsize, blkdta->offsetblock,
                        blkdta->blocknr, blkdta->sparse, 0, 1);
    }
    if (NULL != blkdta->compressed)
        comprfree(blkdta->compressed);
    inuse->inuse = inuse->inuse + 1;
    file_update_inuse(blkdta->stiger, inuse);
    write_dbb_to_cache(&inobno,blkdta->stiger);
    free(inuse);
    EFUNC;
    return;
}

/* delete = 1 Do delete dbdata
   delete = 0 Do not delete dbdta */
unsigned int file_commit_block(unsigned char *dbdata,
                               unsigned char *chksum, INOBNO inobno,
                               bool delete)
{
    unsigned char *stiger;
    compr *compressed;
    INUSE *inuse;
    unsigned int ret = 0;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
#ifdef SHA3
    stiger=sha_binhash(dbdata, BLKSIZE);
#else
    binhash(dbdata, BLKSIZE, res);
    stiger=(unsigned char *)&res;
#endif
#ifdef LZO
    compressed = lzo_compress((unsigned char *) dbdata, BLKSIZE);
#else
    compressed = clz_compress((unsigned char *) dbdata, BLKSIZE);
#endif
    ret = compressed->size;
    inuse = file_get_inuse(stiger);
    if (NULL == inuse) {
        loghash("commit_block : write hash with file_qdta", stiger);
        inuse = s_malloc(sizeof(INUSE));
        inuse->inuse = 0;
        inuse->offset = get_offset(compressed->size);
        inuse->size = compressed->size;
        file_qdta(&inobno, stiger, compressed->data, compressed->size,
                  inuse->offset);
    } else
        loghash("commit_block : only updated inuse for hash ", stiger);
    inuse->inuse++;
    file_update_inuse(stiger, inuse);
    comprfree(compressed);
    write_dbb_to_cache(&inobno,stiger);
#ifdef SHA3
    free(stiger);
#endif
    free(inuse);
    return (ret);
}

/* Read a block of data from file */
DBT *file_tgr_read_data(unsigned char *stiger)
{
    INUSE *inuse = NULL;
    DBT *decrypted = NULL;

    FUNC;
    inuse = file_get_inuse(stiger);
    if (NULL != inuse) {
        if (inuse->inuse == 0)
            die_dataerr("file_tgr_read_data : read empty block");
        decrypted = s_malloc(sizeof(DBT));
        decrypted->data = s_malloc(inuse->size);
        if (inuse->size > BLKSIZE)
            die_dataerr("file_tgr_read_data : unexpected data size, exit");
        decrypted->size =
            (unsigned long) s_pread(fdbdta, decrypted->data, inuse->size,
                                    inuse->offset);
        if (decrypted->size > BLKSIZE)
            die_dataerr("file_tgr_read_data : read empty block");
        free(inuse);
    } else {
        loghash("file_tgr_read_data - unable to find dbdta block hash :",
                stiger);
    }
    EFUNC;
    return decrypted;
}


unsigned long long file_read_block(unsigned long long blocknr,
                                   const char *filename, char *blockdata,
                                   unsigned long long inode)
{
    unsigned long long ret = 0;
    DBT *data = NULL;
    DBT *decrypted = NULL;
    DBT *cachedata;
    unsigned char *stiger;
    unsigned char *dtiger;
    compr *uncompdata = NULL;
    INOBNO inobno;
    BLKCACHE *blk;
    bool compressed = 1;
    QDTA *dta;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    inobno.inode = inode;
    inobno.blocknr = blocknr;
    data = try_block_cache(inode, blocknr, 0);
    if (NULL != data) {
        LDEBUG("file_read_block : block %llu - %llu found in cache", inode,
               blocknr);
        memcpy(blockdata, data->data, data->size);
        ret = data->size;
        DBTfree(data);
        return (ret);
    }
    data = check_block_exists(inobno);
    if (NULL == data) {
        LDEBUG("check_block_exists : Nothing found for inode %llu - %llu",
               inobno.inode, inobno.blocknr);
        LDEBUG("DONE ret = %llu",ret);
        return (ret);
    }
// Not needed to copy this.
    stiger = s_malloc(data->size);
    memcpy(stiger, data->data, data->size);
    DBTfree(data);
// First try the cache
    get_moddb_lock();
    data = search_memhash(dbdtaq, stiger, config->hashlen);
    if (NULL == data) {
        decrypted = file_tgr_read_data(stiger);
        if (NULL != decrypted) {
            LDEBUG
                ("file_read_block : found inode %llu - %llu file_io",
                 inobno.inode, inobno.blocknr);
        } else {

            cachedata =
                search_memhash(blkcache, &inobno.inode,
                               sizeof(unsigned long long));
            if (NULL != cachedata) {
                blk = (BLKCACHE *) cachedata->data;
#ifdef SHA3
                dtiger=sha_binhash(blk->blockdata, BLKSIZE);
#else
                binhash(blk->blockdata, BLKSIZE,res);
                dtiger=(unsigned char *)&res;
#endif
                if (0 == memcmp(dtiger, stiger, config->hashlen)) {
                    decrypted = s_malloc(sizeof(DBT));
                    decrypted->data = s_malloc(BLKSIZE);
                    decrypted->size = BLKSIZE;
                    memcpy(decrypted->data, blk->blockdata, BLKSIZE);
                    compressed = 0;
                }
#ifdef SHA3
                free(dtiger);
#endif
                DBTfree(cachedata);
            }
        }
    } else {
        decrypted = s_malloc(sizeof(DBT));
        dta = (QDTA *) data->data;
        decrypted->data = s_malloc(dta->size);
        memcpy(decrypted->data, dta->data, dta->size);
        decrypted->size = dta->size;
        DBTfree(data);
    }
    release_moddb_lock();
    if (decrypted->size > BLKSIZE)
        die_dataerr("file_read_block : data has grown beyond blocksize %lu",
                    decrypted->size);
    if (compressed && decrypted->size != BLKSIZE) {
#ifdef LZO
        uncompdata = lzo_decompress(decrypted->data, decrypted->size);
#else
        uncompdata = clz_decompress(decrypted->data, decrypted->size);
#endif
        memcpy(blockdata, uncompdata->data, uncompdata->size);
        ret = uncompdata->size;
        comprfree(uncompdata);
    } else {
        memcpy(blockdata, decrypted->data, decrypted->size);
        ret = decrypted->size;
    }
    DBTfree(decrypted);
    free(stiger);
    EFUNC;
    return (ret);
}

QDTA *pull_unsorted_from_dtaq()
{
    unsigned char *kdata;
    unsigned char *vdata;
    QDTA *qdta = NULL;
    QDTA *dta = NULL;
    int ksize;
    int vsize;

    FUNC;
    get_moddb_lock();
    tcmdbiterinit(dbdtaq);
    if ((kdata = tcmdbiternext(dbdtaq, &ksize)) != NULL) {
        vdata = tcmdbget(dbdtaq, kdata, ksize, &vsize);
        qdta = (QDTA *) vdata;
        if (NULL != qdta) {
            dta = s_malloc(sizeof(QDTA));
            memcpy(dta, qdta, sizeof(QDTA));
            mdelete_key(dbdtaq, kdata, config->hashlen);
            free(vdata);
        }
        free(kdata);
    }
    EFUNC;
    release_moddb_lock();
    return dta;
}

void file_sync_flush_dtaq()
{
    QDTA *qdta;
    while (NULL != (qdta = pull_unsorted_from_dtaq())) {
        s_pwrite(fdbdta, qdta->data, qdta->size, qdta->offset);
        free(qdta);
    }
    return;
}

void file_delete_data_cache(unsigned char *chksum, INOBNO * inobno)
{
    loghash("delete_data_cache_or_db : hash not found in dbdta, try cache",
            chksum);
    get_moddb_lock();
    if (!tcmdbout(dbdtaq, chksum, config->hashlen)) {
       loghash("chksum not found",chksum);
    } 
    release_moddb_lock();
    return;
}


/* The freelist is a btree with as key the number
   of blocks (512 bytes). The value is offset.
*/
void put_on_freelist(INUSE * inuse)
{
    unsigned long long calc;
    FUNC;
    int ecode;

    calc = round_512(inuse->size);
    calc = calc / 512;
    if (!tcbdbputdup(freelist, (void *) &calc, sizeof(unsigned long long),
                     (void *) &inuse->offset,
                     sizeof(unsigned long long))) {
        ecode = tcbdbecode(freelist);
        die_dberr("tcbdbputdup failed : %s", tcbdberrmsg(ecode));
    }
    LDEBUG("put_on_freelist : %llu blocks at offset %llu", calc,
           inuse->offset);
    EFUNC;
    return;
}

void file_update_block(const char *blockdata, unsigned long long blocknr,
                       unsigned int offsetblock,
                       unsigned long long size, unsigned long long inode,
                       unsigned char *chksum)
{
    DBT *data = NULL;
    DBT *decrypted = NULL;
    DBT *cachedata;
    unsigned char *dbdata;
    INOBNO inobno;
    compr *uncompdata;
    BLKCACHE *blk;
    unsigned char *dtiger;
    INUSE *inuse;
    bool compressed = 1;
    QDTA *dta;
#ifndef SHA3
    word64 res[3];
#endif

    FUNC;
    LDEBUG
        ("file_update_block : inode %llu blocknr %llu offsetblock %llu, size %llu",
         inode, blocknr, (unsigned long long) offsetblock,
         (unsigned long long) size);
    inobno.inode = inode;
    inobno.blocknr = blocknr;

    dbdata = (unsigned char *) s_malloc(BLKSIZE);
    memset(dbdata, 0, BLKSIZE);
    data = try_block_cache(inode, blocknr, 0);
    if (NULL != data) {
        LDEBUG("try_block_cache : HIT");
        memcpy(dbdata, data->data, data->size);
        memcpy(dbdata + offsetblock, blockdata, size);
        add_blk_to_cache(inode, blocknr, dbdata);
        update_filesize(inode, size, offsetblock, blocknr, 0, 0, 0);
        free(dbdata);
        DBTfree(data);
        return;
    } else
        LDEBUG("update_block: block not found in cache.");

// We don't need the old blockdata when we overwrite it completely anyway.
    if (offsetblock > 0 || size < BLKSIZE) {
        get_moddb_lock();
// First read the cache
        decrypted = search_memhash(dbdtaq, chksum, config->hashlen);
        if (NULL == decrypted) {
            LDEBUG("updateBlock : Not in dbdtaq");
            data = file_tgr_read_data(chksum);
            if (NULL == data) {
                LDEBUG("file_update_block : Not found");
                cachedata =
                    search_memhash(blkcache, &inobno.inode,
                                   sizeof(unsigned long long));
                if (NULL != cachedata) {
                    blk = (BLKCACHE *) cachedata->data;
#ifdef SHA3
                    dtiger=sha_binhash(blk->blockdata, BLKSIZE);
#else
                    binhash(blk->blockdata, BLKSIZE, res);
                    dtiger=(unsigned char *)&res;
#endif
                    if (0 == memcmp(dtiger, chksum, config->hashlen)) {
                        LDEBUG("data alloc here1");
                        data = s_malloc(sizeof(DBT));
                        data->data = s_malloc(BLKSIZE);
                        data->size = BLKSIZE;
                        memcpy(data->data, blk->blockdata, BLKSIZE);
                        DBTfree(cachedata);
                        compressed = 0;
                    } else {
                        LDEBUG
                            ("updateBlock : Not in dbcache, out of luck.");
                        loghash("updateBlock : No data found to read ",
                                chksum);
                        die_dataerr
                            ("file_update_block : No data found to read - this should never happen: inode :%llu: blocknr :%llu",
                             inode, blocknr);
                    }
#ifdef SHA3
                    free(dtiger);
#endif
                } else {
                    log_fatal_hash("file_update_block : No data found to read ",
                            chksum);
                    die_dataerr
                        ("file_update_block : No data found to read, this should never happen: inode :%llu: blocknr :%llu",
                         inode, blocknr);
                }
            }
        } else {
            data = s_malloc(sizeof(DBT));
            dta = (QDTA *) decrypted->data;
            data->data = s_malloc(dta->size);
            memcpy(data->data, dta->data, dta->size);
            data->size = dta->size;
            DBTfree(decrypted);
            LDEBUG("data->size = %lu", data->size);
        }
        release_moddb_lock();
        if (compressed && data->size < BLKSIZE) {
#ifdef LZO
            uncompdata = lzo_decompress(data->data, data->size);
#else
            uncompdata = clz_decompress(data->data, data->size);
#endif
            memcpy(dbdata, uncompdata->data, uncompdata->size);
            comprfree(uncompdata);
        } else {
            memcpy(dbdata, data->data, data->size);
        }
        DBTfree(data);
    }
    memcpy(dbdata + offsetblock, blockdata, size);
    add_blk_to_cache(inode, blocknr, dbdata);
    inuse = file_get_inuse(chksum);
    if (NULL == inuse)
        die_dataerr("file_update_block : hash not found");
    if (inuse->inuse <= 1) {
        file_delete_data_cache(chksum, &inobno);
        put_on_freelist(inuse);
        delete_inuse(chksum);
    } else {
        inuse->inuse--;
        file_update_inuse(chksum, inuse);
    }
    free(inuse);
    update_filesize(inode, size, offsetblock, blocknr, 0, 0, 0);
    free(dbdata);
    EFUNC;
    return;
}

int file_fs_truncate(struct stat *stbuf, off_t size, char *bname)
{
    unsigned int offsetblock;
    unsigned long long blocknr;
    unsigned long long lastblocknr;
    INUSE *inuse;
    unsigned char *stiger;
    off_t oldsize;
    DBT *data;
    INOBNO inobno;
    time_t thetime;

    FUNC;
    LDEBUG("file_fs_truncate inode %llu - size %llu", stbuf->st_ino,
           (unsigned long long) size);
    thetime = time(NULL);
    blocknr = size / BLKSIZE;
    offsetblock = size - (blocknr * BLKSIZE);
    oldsize = stbuf->st_size;
    lastblocknr = oldsize / BLKSIZE;
    update_filesize_cache(stbuf, size);
    LDEBUG("file_fs_truncate : truncate new block %llu, oldblock %llu",
           blocknr, lastblocknr);
    while (lastblocknr >= blocknr) {
        if ( offsetblock != 0 && lastblocknr == blocknr ) break;
        LDEBUG
            ("file_fs_truncate : Enter loop lastblocknr %llu : blocknr %llu",
             lastblocknr, blocknr);
        inobno.inode = stbuf->st_ino;
        inobno.blocknr = lastblocknr;
        get_dbb_lock();
        data = search_memhash(dbbm, &inobno, sizeof(INOBNO));
        if ( NULL == data ) {
            data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
        }
        release_dbb_lock();
        if (NULL == data) {
            LDEBUG
                ("file_fs_truncate: deletion of non existent block inode : %llu, blocknr %llu",
                 inobno.inode, inobno.blocknr);
            if (lastblocknr > 0)
                lastblocknr--;
            else
                break;
// Need to continue in case of a sparse file.
            continue;
        }
        stiger = s_malloc(data->size);
        memcpy(stiger, data->data, data->size);
        LDEBUG
            ("file_fs_truncate : lessfs_truncate Search to delete blocknr %llu:",
             lastblocknr);
        loghash("file_fs_truncate : tiger :", stiger);
        DBTfree(data);
        inuse = file_get_inuse(stiger);
        if (NULL == inuse)
            die_dataerr("file_fs_truncate : unexpected data error.");
        if (inuse->inuse == 1) {
            sync_flush_dtaq();
            put_on_freelist(inuse);
            loghash("file_fs_truncate : delete_inuse ",stiger); 
            delete_inuse(stiger);
            LDEBUG("file_fs_truncate : delete dbb %llu-%llu",inobno.inode,inobno.blocknr);
            delete_dbb(&inobno);
        } else {
            if (inuse->inuse > 1)
                inuse->inuse--;
            LDEBUG("file_fs_truncate : delete dbb %llu-%llu",inobno.inode,inobno.blocknr);
            delete_dbb(&inobno);
            file_update_inuse(stiger, inuse);
        }
        free(inuse);
        if (lastblocknr > 0)
            lastblocknr--;
        free(stiger);
    }
    LDEBUG("offsetblock = %u", offsetblock);
    if (0 != offsetblock)
        file_partial_truncate_block(stbuf, lastblocknr, offsetblock);
    return (0);
}

void file_partial_truncate_block(struct stat *stbuf,
                                 unsigned long long blocknr,
                                 unsigned int offset)
{
    unsigned char *blockdata;
    compr *uncompdata;
    INOBNO inobno;
    DBT *data;
    unsigned char *stiger;
    INUSE *inuse;
    DBT cachedata;
    QDTA *dta;

    FUNC;
    LDEBUG("file_partial_truncate_block : inode %llu, blocknr %llu, offset %u",
           stbuf->st_ino, blocknr, offset);
    inobno.inode = stbuf->st_ino;
    inobno.blocknr = blocknr;
    get_dbb_lock();
    data = search_memhash(dbbm, &inobno, sizeof(INOBNO));
    if ( NULL == data ) {
       data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
    }
    release_dbb_lock();
    if (NULL == data) {
        LDEBUG("file_partial_truncate_block : deletion of non existent block.");
        return;
    }
    stiger = s_malloc(data->size);
    loghash("file_partial_truncate_block : search tiger ", stiger);
    memcpy(stiger, data->data, data->size);
    DBTfree(data);

    blockdata = s_malloc(BLKSIZE);
    memset(blockdata, 0, BLKSIZE);
// First try the cache
    get_moddb_lock();
       data = search_memhash(dbdtaq, stiger, config->hashlen);
       if ( NULL != data ) die_dataerr("file_partial_truncate_block : not data in cache expected");
    release_moddb_lock();
    if ( NULL == data ) {
       data = file_tgr_read_data(stiger);
       if ( NULL != data ) {
          LDEBUG("file_partial_truncate_block : clz_decompress");
          if (data->size != BLKSIZE) {
#ifdef LZO
              uncompdata = lzo_decompress(data->data, data->size);
#else
              uncompdata = clz_decompress(data->data, data->size);
#endif
              memcpy(blockdata, uncompdata->data, offset);
              comprfree(uncompdata);
          } else {
              memcpy(blockdata, data->data, offset);
          }
          file_commit_block(blockdata,NULL,inobno,0);
          DBTfree(data);
       }
    } else {
       dta = (QDTA *)data->data;
       cachedata.data=s_malloc(dta->size);
       memcpy(cachedata.data, dta->data, dta->size);
       cachedata.size = dta->size;
       memcpy(blockdata, cachedata.data, offset);
       free(cachedata.data);
       DBTfree(data);
       file_commit_block(blockdata,NULL,inobno,0);
    }
    free(blockdata);

    inuse = file_get_inuse(stiger);
    if (NULL == inuse)
        die_dataerr
            ("file_partial_truncate_block : unexpected block not found");
    if (inuse->inuse == 1) {
        loghash("file_partial_truncate_block : delete hash", stiger);
        put_on_freelist(inuse);
        delete_inuse(stiger);
    } else {
        if (inuse->inuse > 1)
            inuse->inuse--;
        file_update_inuse(stiger, inuse);
    }
    free(inuse);
    free(stiger);
    return;
}

int file_unlink_file(const char *path)
{
    int res = 0;
    int haslinks = 0;
    int dir_links = 0;
    struct stat st;
    struct stat dirst;
    char *dname;
    char *bname;
    unsigned char *stiger;
    unsigned long long inode;
    unsigned long long counter = 0;
    INUSE *inuse;
    unsigned long long done = 0;
    time_t thetime;
    void *vdirnode;
    DBT *bdata;
    DBT *ddbuf;
    DBT *dataptr;
    DDSTAT *ddstat;
    DINOINO dinoino;
    INOBNO inobno;
    char *filename;

    FUNC;

    LDEBUG("unlink_file %s", path);
    res = dbstat(path, &st);
    if (res == -ENOENT)
        return (res);
    inode = st.st_ino;
    haslinks = st.st_nlink;
    thetime = time(NULL);
    dname = s_dirname((char *) path);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    res = update_parent_time(dname,0);
    bname = s_basename((char *) path);
    res = dbstat(dname, &dirst);
    if (S_ISLNK(st.st_mode) && haslinks == 1) {
        LDEBUG("unlink symlink %s inode %llu", path, inode);
        delete_key(dbs, &inode, sizeof(unsigned long long));
        LDEBUG("unlink symlink done %s", path);
    }
    inobno.inode = inode;
    inobno.blocknr = counter;
    while (done < st.st_size) {
        get_dbb_lock();
        bdata = search_memhash(dbbm, &inobno, sizeof(INOBNO));
        if ( NULL == bdata ) {
           bdata = search_dbdata(dbb, &inobno, sizeof(INOBNO));
        }
        release_dbb_lock();
        if (bdata == NULL) {
            LDEBUG("%llu is sparse", counter);
            done = done + BLKSIZE;
            counter++;
            inobno.blocknr = counter;
            continue;
        }
        stiger = s_malloc(bdata->size);
        memcpy(stiger, bdata->data, bdata->size);
        loghash("search inuse for ", stiger);
        inuse = file_get_inuse(stiger);
        if (NULL != inuse) {
           if (haslinks == 1) {
               if (inuse->inuse == 1) {
                   loghash("unlink_file delete dbu,dbdta for ", stiger);
                   delete_inuse(stiger);
                   put_on_freelist(inuse);
               } else {
                   if (inuse->inuse > 1)
                       inuse->inuse--;
                   loghash("updateInUse dbu,dbdta for ", stiger);
                   file_update_inuse(stiger, inuse);
               }
           }
           free(inuse);
        } else log_fatal_hash("unlink_file inuse not found",stiger);
        free(stiger);
        DBTfree(bdata);
        if (haslinks == 1) {
            LDEBUG("unlink_file : delete inode %llu - %llu", inobno.inode,
                   inobno.blocknr);
            delete_dbb(&inobno);
        }
        counter++;
        inobno.blocknr = counter;
        done = done + BLKSIZE;
    }
    if (haslinks == 1) {
        if (0 !=
            (res =
             btdelete_curkey(dbdirent, &dirst.st_ino,
                             sizeof(unsigned long long), &inode,
                             sizeof(unsigned long long)))) {
            free(bname);
            free(dname);
            return (res);
        }
        delete_key(dbp, (unsigned char *) &inode,
                   sizeof(unsigned long long));
    } else {
        dataptr =
            search_dbdata(dbp, (unsigned char *) &inode,
                          sizeof(unsigned long long));
        if (dataptr == NULL) {
            die_dataerr("Failed to find file %llu", inode);
        }
        ddstat = value_to_ddstat(dataptr);
        ddstat->stbuf.st_nlink--;
        ddstat->stbuf.st_ctim.tv_sec = thetime;
        ddstat->stbuf.st_ctim.tv_nsec=0;
        ddstat->stbuf.st_mtim.tv_sec = thetime;
        ddstat->stbuf.st_mtim.tv_nsec=0;
        dinoino.dirnode = dirst.st_ino;
        dinoino.inode = ddstat->stbuf.st_ino;
        dir_links = count_dirlinks(&dinoino, sizeof(DINOINO));
        res =
            btdelete_curkey(dbl, &dinoino, sizeof(DINOINO), bname,
                            strlen(bname));
        btdelete_curkey(dbl, &ddstat->stbuf.st_ino,
                        sizeof(unsigned long long), &dinoino,
                        sizeof(DINOINO));
// Restore to regular file settings and clean up.
        if (ddstat->stbuf.st_nlink == 1) {
            vdirnode =
                btsearch_keyval(dbl, &ddstat->stbuf.st_ino,
                                sizeof(unsigned long long), NULL, 0);
            memcpy(&dinoino, vdirnode, sizeof(DINOINO));
            free(vdirnode);
            filename =
                (char *) btsearch_keyval(dbl, &dinoino, sizeof(DINOINO),
                                         NULL, 0);
            memcpy(&ddstat->filename, filename, strlen(filename) + 1);
            free(filename);
            LDEBUG
                ("unlink_file : Restore %s to regular file settings and clean up.",
                 ddstat->filename);
            btdelete_curkey(dbl, &dinoino, sizeof(DINOINO),
                            ddstat->filename, strlen(ddstat->filename));
            btdelete_curkey(dbl, &ddstat->stbuf.st_ino,
                            sizeof(unsigned long long), &dinoino,
                            sizeof(DINOINO));
            btdelete_curkey(dbl, &inode, sizeof(unsigned long long),
                            &dinoino, sizeof(DINOINO));
            res = 0;
        }
        if (dir_links == 1) {
            if (0 !=
                (res =
                 btdelete_curkey(dbdirent, &dirst.st_ino,
                                 sizeof(unsigned long long), &inode,
                                 sizeof(unsigned long long)))) {
                die_dataerr("unlink_file : Failed to delete record.");
            }
        }
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
        bin_write_dbdata(dbp, &inode,
                         sizeof(unsigned long long), (void *) ddbuf->data,
                         ddbuf->size);
        DBTfree(dataptr);
        DBTfree(ddbuf);
        ddstatfree(ddstat);
    }
    free(bname);
    free(dname);
    EFUNC;
    return (res);
}
