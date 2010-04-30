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

#define FUSE_USE_VERSION 26
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef LFATAL
#include "lib_log.h"
#endif

#ifndef VERSION
#define VERSION "0"
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <libgen.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <tcutil.h>
#include <tchdb.h>
#include <tcbdb.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "lib_net.h"
#include "file_io.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include "lib_safe.h"
#include "lib_cfg.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef ENABLE_CRYPTO
#include "lib_crypto.h"
#endif
#ifdef SHA3
#include "lib_BMW_SHA3api_ref.h"
#endif

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif
#include "commons.h"

void segvExit()
{
    LFATAL("Exit caused by segfault!, exitting\n");
    tc_close(0);
    exit(EXIT_OK);
}

void normalExit()
{
    LFATAL("Exit signal received, exitting\n");
    tc_close(0);
    exit(EXIT_OK);
}

void libSafeExit()
{
    tc_close(0);
    LFATAL("Exit signal received from lib_safe, exitting\n");
    exit(EXIT_OK);
}

int check_path_sanity(const char *path)
{
    char *name;
    char *p;
    char *q;
    int retcode = 0;

    FUNC;
    LDEBUG("check_path_sanity : %s", path);

    name = s_strdup((char *) path);
    p = name;
    q = p;
    while (1) {
        p = strrchr(q, '/');
        if (p == NULL)
            break;
        q = p;
        q++;
        p[0] = 0;
        if (q) {
            if (strlen(q) > 255) {
                LDEBUG("check_path_sanity : error q>255");
                retcode = -ENAMETOOLONG;
            }
        }
        q = p--;
    }
    free(name);
    EFUNC;
    return (retcode);
}

void dbsync()
{
    tcbdbsync(dbdirent);
    tchdbsync(dbu);
    tchdbsync(dbb);
    tchdbsync(dbp);
    if (NULL != config->blockdatabs) {
        tchdbsync(dbdta);
    } else {
        fsync(fdbdta);
    }
}

static int lessfs_getattr(const char *path, struct stat *stbuf)
{
    int res;
    int c;

    FUNC;
    LDEBUG("lessfs_getattr %s", path);
    res = check_path_sanity(path);
    if (res == -ENAMETOOLONG)
        return (res);

    get_global_lock();
    res = dbstat(path, stbuf);
    LDEBUG("lessfs_getattr : st_nlinks=%u", stbuf->st_nlink);
    LDEBUG("lessfs_getattr : %s size %llu : result %i",path,
           (unsigned long long) stbuf->st_size, res);
    release_global_lock();
    return (res);
}

static int lessfs_access(const char *path, int mask)
{
    int res = 0;
    FUNC;
// Empty stub
    return (res);
}

static int lessfs_readlink(const char *path, char *buf, size_t size)
{
    int res = 0;

    FUNC;

    LDEBUG("lessfs_readlink : size = %i", (int) size);
    get_global_lock();
    res = fs_readlink(path, buf, size);
    release_global_lock();
    return (res);
}


static int lessfs_readdir(const char *path, void *buf,
                          fuse_fill_dir_t filler, off_t offset,
                          struct fuse_file_info *fi)
{
    int retcode;
    get_global_lock();
    retcode = fs_readdir(path, buf, filler, offset, fi);
    release_global_lock();
    return (retcode);
}

static int lessfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int retcode = 0;
    char *dname;
    struct stat stbuf;
    time_t thetime;

    FUNC;
    get_global_lock();
    thetime = time(NULL);
    dname = s_dirname((char *) path);
    retcode = dbstat(dname, &stbuf);
    LDEBUG("lessfs_mknod : dbstat returns %i", retcode);
    if (0 != retcode)
        return retcode;
    dbmknod(path, mode, NULL, rdev);
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    retcode = update_stat(dname, &stbuf);
    LDEBUG("lessfs_mknod : update_stat returns %i", retcode);
    free(dname);
    release_global_lock();
    return (retcode);
}

static int lessfs_mkdir(const char *path, mode_t mode)
{
    int ret;
    get_global_lock();
    ret = fs_mkdir(path, mode);
    release_global_lock();
    return (ret);
}

static int lessfs_unlink(const char *path)
{
    int res;
    FUNC;
    get_global_lock();
    tiger_lock();
    if (NULL != config->blockdatabs) {
        res = db_unlink_file(path);
    } else {
        res = file_unlink_file(path);
    }
    if ( config->relax == 0 ) dbsync();
    release_tiger_lock();
    release_global_lock();
    EFUNC;
    return res;
}

static int lessfs_rmdir(const char *path)
{
    int res;
    get_global_lock();
    res = fs_rmdir(path);
    release_global_lock();
    return (res);

}

static int lessfs_symlink(const char *from, const char *to)
{
    int res = 0;

    FUNC;
    get_global_lock();
    res = fs_symlink((char *) from, (char *) to);
    release_global_lock();
    return (res);
}

static int lessfs_rename(const char *from, const char *to)
{
    int res = 0;
    struct stat stbuf;

    FUNC;
    LDEBUG("lessfs_rename : from %s , to %s", from, to);
    get_global_lock();
    res = dbstat(from, &stbuf);
    if (res == 0) {
        update_filesize_onclose(stbuf.st_ino);
        if (stbuf.st_nlink > 1 && !S_ISDIR(stbuf.st_mode)) {
            res = fs_rename_link(from, to, stbuf);
        } else {
            res = fs_rename(from, to, stbuf);
        }
    }
    release_global_lock();
    return (res);
}

static int lessfs_link(const char *from, const char *to)
{
    int res = 0;

    FUNC;
    get_global_lock();
    res = fs_link((char *) from, (char *) to);
    release_global_lock();
    return (res);
}

static int lessfs_chmod(const char *path, mode_t mode)
{
    int res;
    time_t thetime;
    struct stat stbuf;
    DBT *data;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;

    FUNC;
    LDEBUG("lessfs_chmod : %s", path);
    get_global_lock();
    thetime = time(NULL);
    res = dbstat(path, &stbuf);
    if ( res != 0 ) return(res);
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mode = mode;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        stbuf.st_mode = mode;
        stbuf.st_ctim.tv_sec = thetime;
        stbuf.st_ctim.tv_nsec=0;
        res = update_stat((char *) path, &stbuf);
    }
    release_global_lock();
    return (res);
}

static int lessfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    time_t thetime;
    struct stat stbuf;
    DBT *data;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;

    FUNC;
    get_global_lock();
    thetime = time(NULL);
    res = dbstat(path, &stbuf);
    if ( res != 0 ) return(res);
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_uid = uid;
        memddstat->stbuf.st_gid = gid;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        if (-1 != uid)
           stbuf.st_uid = uid;
        if (-1 != gid)
           stbuf.st_gid = gid;
        stbuf.st_ctim.tv_sec = thetime;
        stbuf.st_ctim.tv_nsec=0;
        res = update_stat((char *) path, &stbuf);
    }
    release_global_lock();
    return (res);
}

static int lessfs_truncate(const char *path, off_t size)
{
    int res = 0;
    struct stat *stbuf;
    char *bname;
    DBT *data;
 
    get_global_lock();
    bname = s_basename((char *) path);
    stbuf = s_malloc(sizeof(struct stat));
    res = dbstat(path, stbuf);
    if (res != 0) {
        release_global_lock();
        return (res);
    }
    if (S_ISDIR(stbuf->st_mode)) {
        release_global_lock();
        return (-EISDIR);
    }
    LDEBUG("lessfs_truncate : %s truncate from %llu to %llu",path,stbuf->st_size,size);
    /* Flush the blockcache before we continue. */
    tiger_lock();
    flush_wait(stbuf->st_ino);
    if ( size < stbuf->st_size ) {
    //if ( size < stbuf->st_size || size == 0 ) {
       if (NULL != config->blockdatabs) {
           res = db_fs_truncate(stbuf, size, bname);
       } else {
           res = file_fs_truncate(stbuf, size, bname);
       }
    } else {
       LDEBUG("lessfs_truncate : %s only change size to %llu",path,size);
       update_filesize_cache(stbuf,size);
    }
    release_tiger_lock();
    free(stbuf);
    free(bname);
    release_global_lock();
    return (res);
}

static int lessfs_utimens(const char *path, const struct timespec ts[2])
{
    int res = 0;
    struct stat stbuf;
    DDSTAT *ddstat;
    DBT *ddbuf;
    DBT *data;
    MEMDDSTAT *memddstat;

    FUNC;
    get_global_lock();
    res = dbstat(path, &stbuf);
    if ( res != 0 ) {
       release_global_lock();
       return(res);
    }
    data = search_memhash(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long));
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data->data;
        memddstat->stbuf.st_atim.tv_sec = ts[0].tv_sec;
        memddstat->stbuf.st_atim.tv_nsec = ts[0].tv_nsec;
        memddstat->stbuf.st_mtim.tv_sec = ts[1].tv_sec;
        memddstat->stbuf.st_mtim.tv_nsec = ts[1].tv_nsec;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        mbin_write_dbdata(dbcache, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
        DBTfree(data);
    } else {
        data =
            search_dbdata(dbp, &stbuf.st_ino, sizeof(unsigned long long));
        if (data == NULL) {
#ifdef x86_64
            die_dataerr("Failed to find file %lu", stbuf.st_ino);
#else
            die_dataerr("Failed to find file %llu", stbuf.st_ino);
#endif
        }
        ddstat = value_to_ddstat(data);
        ddstat->stbuf.st_atim.tv_sec = ts[0].tv_sec;
        ddstat->stbuf.st_atim.tv_nsec = ts[0].tv_nsec;
        ddstat->stbuf.st_mtim.tv_sec = ts[1].tv_sec;
        ddstat->stbuf.st_mtim.tv_nsec = ts[1].tv_nsec;
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename);
        bin_write_dbdata(dbp, &stbuf.st_ino, sizeof(unsigned long long),
                         (void *) ddbuf->data, ddbuf->size);
        DBTfree(data);
        DBTfree(ddbuf);
        ddstatfree(ddstat);
    }
    release_global_lock();
    return (res);
}

static int lessfs_open(const char *path, struct fuse_file_info *fi)
{
    struct stat stbuf;
    char *bname;
    DBT *ddbuf;
    DBT *dataptr;
    unsigned long long blocknr = 0;
    MEMDDSTAT *memddstat;
    unsigned long long inode;

    int res = 0;

    FUNC;
    LDEBUG("lessfs_open : %s strlen %i : uid %u", path,
           strlen((char *) path), fuse_get_context()->uid);

    get_global_lock();
    res = dbstat(path, &stbuf);
    if (res == -ENOENT) {
        fi->fh = 0;
        stbuf.st_mode = fi->flags;
        stbuf.st_uid = fuse_get_context()->uid;
        stbuf.st_gid = fuse_get_context()->gid;
    } else {
        fi->fh = stbuf.st_ino;
        inode = stbuf.st_ino;
        tiger_lock();
        flush_wait(inode);
        release_tiger_lock();
        bname = s_basename((char *) path);
//  Check if we have already something in cache for this inode
        dataptr =
            search_memhash(dbcache, &stbuf.st_ino,
                           sizeof(unsigned long long));
        if (dataptr == NULL) {
            blocknr--;          /* Invalid block in cache */
//  Initialize the cache
            memddstat = s_malloc(sizeof(MEMDDSTAT));
            memcpy(&memddstat->stbuf, &stbuf, sizeof(struct stat));
            memcpy(&memddstat->filename, bname, strlen(bname) + 1);
            memddstat->blocknr = blocknr;
            memddstat->updated = 0;
            memddstat->opened = 1;
            memddstat->deduplicated = 0;
            memddstat->lzo_compressed_size = 0;
            memddstat->stbuf.st_atim.tv_sec=time(NULL);
            memddstat->stbuf.st_atim.tv_nsec=0;
            LDEBUG("lessfs_open : initial open memddstat->opened = %u",
                   memddstat->opened);
            ddbuf = create_mem_ddbuf(memddstat);
            mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            memddstatfree(memddstat);
        } else {
            memddstat = (MEMDDSTAT *) dataptr->data;
            memddstat->opened++;
            memddstat->stbuf.st_atim.tv_sec=time(NULL);
            memddstat->stbuf.st_atim.tv_nsec=0;
            LDEBUG("lessfs_open : repeated open ddstat->opened = %u",
                   memddstat->opened);
            ddbuf = create_mem_ddbuf(memddstat);
            mbin_write_dbdata(dbcache, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            DBTfree(dataptr);
        }
        free(bname);
    }
    release_global_lock();
    EFUNC;
    return (res);
}

static int lessfs_read(const char *path, char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    unsigned long long blocknr;
    size_t done = 0;
    size_t got = 0;
    size_t block_offset = 0;
    char *tmpbuf = NULL;
    int pass=0;

    FUNC;

    get_global_lock();
// Change this to creating a buffer that is allocated once.
    tmpbuf = s_malloc(BLKSIZE + 1);
    memset(buf, 0, size);
    memset(tmpbuf, 0, BLKSIZE + 1);
    LDEBUG("lessfs_read called offset : %llu, size bytes %llu",
           (unsigned long long) offset, (unsigned long long) size);
    while (done < size) {
        blocknr = (offset + done) / BLKSIZE;
        LDEBUG("blocknr to read :%llu", (unsigned long long) blocknr);
        block_offset = (done + offset) - (blocknr * BLKSIZE);
        if (NULL != config->blockdatabs) {
            got = readBlock(blocknr, path, tmpbuf, fi->fh, size-done);
            LDEBUG("readBlock : %llu-%llu returns %i bytes",fi->fh,blocknr,got);
        } else
            got = file_read_block(blocknr, path, tmpbuf, fi->fh);
        if (got > 0) {
            if ((got - block_offset) + done >= size) {
                memcpy(buf + done, tmpbuf + block_offset, size - done);
                done = size;
                break;
            }
            memcpy(buf + done, tmpbuf + block_offset, got - block_offset);
            done = done + got - block_offset;
        } else {
// Nothing found to read, this might be a sparse block, if so return
// size and fill the block with zeros
              if (got == 0) {
                  if ( pass == 0 ) {
                     done=done+(BLKSIZE-block_offset);
                     if ( done > size ) done=size;
                  } else {
                     done=size;
                  }
                  LDEBUG("lessfs_read : sparse block %llu-%llu offset %llu size %llu",\
                          fi->fh,blocknr,(unsigned long long) offset,(unsigned long long) size);
              }
        }
        pass++;
    }
    free(tmpbuf);
    release_global_lock();
    return (done);
}

CCACHEDTA *update_stored(char *hash, INOBNO *inobno, off_t offsetblock)
{
   DBT *encrypted;
   DBT *data;
   unsigned char *dbdata;
   compr *uncompdata;
   CCACHEDTA *ccachedta;
   unsigned long long inuse;

   ccachedta=s_zmalloc(sizeof(CCACHEDTA));
   ccachedta->creationtime=time(NULL);
   ccachedta->dirty=1;
   ccachedta->pending=0;

#ifdef ENABLE_CRYPTO
   encrypted = search_dbdata(dbdta, hash, config->hashlen);
   if (NULL == encrypted) {
#else
   data = search_dbdata(dbdta, hash, config->hashlen);
   if (NULL == data) {
#endif

#ifndef ENABLE_CRYPTO
   }
#else
   } else {
      if (config->encryptdata) {
         data = decrypt(encrypted);
         DBTfree(encrypted);
      } else
         data = encrypted;
   }
#endif
   if (data->size < BLKSIZE) {
#ifdef LZO
      uncompdata = lzo_decompress(data->data, data->size);
#else
      LDEBUG("uncomp data");
      uncompdata = clz_decompress(data->data, data->size);
      LDEBUG("done uncomp data");
#endif
      LDEBUG("got uncompsize : %lu", uncompdata->size);
      memcpy(&ccachedta->data, uncompdata->data, uncompdata->size);
      comprfree(uncompdata);
   } else {
      LDEBUG("Got data->size %lu", data->size);
      memcpy(&ccachedta->data, data->data, data->size);
   }
   DBTfree(data);
   delete_dbb(inobno);
   inuse = getInUse(hash);
   if (inuse <= 1) {
        delete_inuse(hash);
        if (!tchdbout(dbdta, hash, config->hashlen)) {
        loghash
            ("Failed to delete hash from dbdta",
             hash);
        }
   } else {
        inuse--;
        update_inuse(hash, inuse);
   }
   EFUNC;
   return ccachedta;
}

void add2cache (INOBNO *inobno, const char *buf, off_t offsetblock, size_t bsize )
{
   CCACHEDTA *ccachedta;
   unsigned long long p;
   int size;
   char *key;
   DBT *data=NULL;
   DBT *rdata;

   update_filesize(inobno->inode, bsize, offsetblock,
                   inobno->blocknr, 0, BLKSIZE, 0);
   FUNC;
   tiger_lock();
   key=(char *)tctreeget(rdtree, (void *)inobno, sizeof(INOBNO), &size);
   if ( NULL != key ) {
     LDEBUG("Found %llu-%llu in rdtree",inobno->inode,inobno->blocknr);
     memcpy(&p,key,size);
     ccachedta=(CCACHEDTA *)p;
     ccachedta->creationtime=time(NULL);
     while(ccachedta->pending == 1 ) {
         LFATAL("Wait on pending");
     }
     ccachedta->dirty=1;
     ccachedta->pending=0;
     LDEBUG("Set ccachedta->dirty=1 for %llu-%llu",inobno->inode,inobno->blocknr);
     memcpy((void *)&ccachedta->data[offsetblock],buf,bsize);
     release_tiger_lock();
     EFUNC;
     return;
   }

   if ( bsize < BLKSIZE ) {
      data=check_block_exists(inobno); 
      if ( NULL != data ) {
         ccachedta=update_stored(data->data, inobno, offsetblock);
         memcpy(&ccachedta->data[offsetblock],buf,bsize);
         DBTfree(data);
      }
   } 
   if ( NULL == data ) {
      ccachedta=s_zmalloc(sizeof(CCACHEDTA));
      memcpy(&ccachedta->data[offsetblock],buf,bsize);
      ccachedta->creationtime=time(NULL);
      ccachedta->dirty=1;
      ccachedta->pending=0;
   }
   p=(unsigned long long)ccachedta;
// A full block can be processed right away.
   if ( bsize == BLKSIZE ) {
      LDEBUG("Write %llu-%llu to cachetree",inobno->inode,inobno->blocknr);
      tctreeput(cachetree, (void *)inobno, sizeof(INOBNO), (void *)&p, sizeof(unsigned long long));
   }
// When this is not a full block a separate thread is used.
   LDEBUG("Write %llu-%llu to rdtree",inobno->inode,inobno->blocknr);
   tctreeput(rdtree, (void *)inobno, sizeof(INOBNO), (void *)&p, sizeof(unsigned long long));
   release_tiger_lock();
   EFUNC;
   return;
}

static int lessfs_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi)
{
    off_t offsetblock;
    DBT *blocktiger;
    DBT *data;
    size_t bsize;
    size_t done = 0;
    int res;
    INOBNO inobno;
    int count=0;

    FUNC;

    get_global_lock();
    LDEBUG("lessfs_write offset %llu size %lu", offset, (unsigned long)size);
    inobno.inode = fi->fh;
    while ( 1 )
    {
        inobno.blocknr = ( offset + done ) / BLKSIZE;
        offsetblock = offset + done - (inobno.blocknr * BLKSIZE);
        bsize = size-done;
        if ( bsize + offsetblock > BLKSIZE ) bsize=BLKSIZE-offsetblock;
        //Just put it in cache. We might need to fetch the block.
        //This is done by add2cache.
        add2cache(&inobno, buf+done,offsetblock,bsize);
        done=done+bsize;
        bsize=size-done;
        if ( done >= size ) break;
    }
    release_global_lock();
    EFUNC;
    return (size);
}

static int lessfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char *blockdatadir;

    if (NULL != config->blockdatabs) {
        res = statvfs(config->blockdata, stbuf);
    } else {
        blockdatadir = s_dirname(config->blockdata);
        res = statvfs(blockdatadir, stbuf);
        free(blockdatadir);
    }
    if (res == -1)
        return -errno;
    return 0;
}

static int lessfs_release(const char *path, struct fuse_file_info *fi)
{
    DBT *dataptr;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    DBT *data;

    FUNC;
// Finish pending i/o for this inode.
    get_global_lock();
    tiger_lock();
    flush_wait(fi->fh);
    release_tiger_lock();
    dataptr = search_memhash(dbcache, &fi->fh, sizeof(unsigned long long));
    if (dataptr != NULL) {
        memddstat = (MEMDDSTAT *) dataptr->data;
        if (memddstat->opened == 1) {
// Update the filesize when needed.
            update_filesize_onclose(fi->fh);
#ifdef x86_64
            LINFO
                ("File %s size %lu bytes : lzo compressed bytes %llu and %llu duplicate blocks",
                 path, memddstat->stbuf.st_size,
                 memddstat->lzo_compressed_size, memddstat->deduplicated);
#else
            LINFO
                ("File %s size %llu bytes : lzo compressed bytes %llu and %llu duplicate blocks",
                 path, memddstat->stbuf.st_size,
                 memddstat->lzo_compressed_size, memddstat->deduplicated);
#endif
            LINFO("File %s compression ratio : 1 : %f", path,
                   (float) memddstat->stbuf.st_size /
                   memddstat->lzo_compressed_size);
            LDEBUG("lessfs_release : Delete cache for %llu", fi->fh);
            mdelete_key(dbcache, &fi->fh, sizeof(unsigned long long));
            if ( NULL == config->blockdatabs) fdatasync(fdbdta);
        } else {
            memddstat->opened--;
            ddbuf = create_mem_ddbuf(memddstat);
            LDEBUG("lessfs_release : %llu is now %u open", fi->fh,
                   memddstat->opened);
            mbin_write_dbdata(dbcache, &fi->fh, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
        }
        DBTfree(dataptr);
    }
    (void) path;
    (void) fi;
    release_global_lock();
    EFUNC;
    return 0;
}

static int lessfs_fsync(const char *path, int isdatasync,
                        struct fuse_file_info *fi)
{
    DBT *data;
    FUNC;
    (void) path;
    (void) isdatasync;
    get_global_lock();
    tiger_lock();
    flush_wait(fi->fh);
    release_tiger_lock();
    /* Living on the edge, wait for pending I/O but do not flush the caches. */
    if (config->relax < 2) {
        update_filesize_onclose(fi->fh);
    }
    /* When config->relax == 1 dbsync is not called but the caches within lessfs
       are flushed making this a safer option. */
    if (config->relax == 0)
        dbsync();
    release_global_lock();
    EFUNC;
    return 0;
}

static void lessfs_destroy(void *unused __attribute__ ((unused)))
{
    FUNC;
    if ( config->transactions) lessfs_trans_stamp();
    clear_dirty();
    tc_close(0);
#ifdef ENABLE_CRYPTO
    if (config->encryptdata){
       free(config->passwd);
       free(config->iv);
    }
#endif
    if ( config->transactions ) {
       free(config->commithash);
    }
    free(config);
    EFUNC;
    return;
}

/*  Return 0 when enough space free
    Return 1 at MIN_SPACE_FREE
    Return 2 at MIN_SPACE_CLEAN 
*/
int check_free_space(char *dbpath)
{
    float dfull;
    int mf, mc;
    char *minfree;
    char *minclean;
    struct statfs sb;

    if (-1 == statfs(dbpath, &sb))
        die_dataerr("Failed to stat : %s", dbpath);
    dfull = (float) sb.f_blocks / (float) sb.f_bfree;
    dfull = 100 / dfull;
    minfree = getenv("MIN_SPACE_FREE");
    minclean = getenv("MIN_SPACE_CLEAN");
    if (NULL != minfree) {
        mf = atoi(minfree);
        if (mf > 100 || mf < 1)
            mf = 10;
    } else {
        mf = 10;
    }
    /* Freeze has a higher prio then clean */
    if (dfull <= mf) {
        return (1);
    }
    if (NULL != minclean) {
        mc = atoi(minclean);
        if (mc > 100 || mc < 1)
            mc = 15;
    } else {
        mc = 0;
    }
    if (dfull <= mc ) {
        return(2);
    }
    return (0);
}

void freeze_nospace(char *dbpath)
{
    LFATAL
        ("Filesystem for database %s has insufficient space to continue, freezing I/O",
         dbpath);
    get_global_lock();
    tc_close(1);
    LFATAL("All IO is now suspended until space comes available.");
    LFATAL
        ("If no other options are available it should be safe to kill lessfs.");
    while (1) {
        if (0 == check_free_space(dbpath)) {
            tc_open(1,0);
            release_global_lock();
            break;
        }
        sleep(1);
    }
    LFATAL("Resuming IO : sufficient space available.");
}

void *queue_gard(void *arg)
{
   while(1)
   {
      sleep(1);
      if ( config->cachesize/2 < tctreernum(rdtree)*sizeof(CCACHEDTA) ||\
           config->cachesize/2 < tctreernum(cachetree)*sizeof(CCACHEDTA)){
         LDEBUG("queue_gard : force to drain the cache");
         get_global_lock();
         tiger_lock();
         flush_queue(0, 1); 
         release_tiger_lock();
         release_global_lock();
      }
   }
}

void exec_clean_program()
{
   char *program;
   pid_t rpid;
   int res = 1;
   /* We can read and log output from the program. */
   int commpipe[2];

   FUNC;

   program=getenv("CLEAN_PROGRAM");
   if ( NULL == program) {
      LINFO("CLEAN_PROGRAM is not defined");
      return;
   }

   LINFO("exec_clean_program : execute %s",program);
   if (pipe(commpipe) == -1) {
        LFATAL("Failed to open pipe.");
        return;
   }
   /* Attempt to fork and check for errors */
   if ((rpid = fork()) == -1) {
       LFATAL("Fork error. Exiting.\n");      /* something went wrong */
       return;
   }
   if (rpid) {
       /* A positive (non-negative) PID indicates the parent process */
       dup2(commpipe[0], 0);   /* Replace stdout with out side of the pipe */
       close(commpipe[1]);     /* Close unused side of pipe (in side) */
       setvbuf(stdout, (char *) NULL, _IONBF, 0);      /* Set non-buffered output on stdout */
       wait(&res);
   } else {
       /* A zero PID indicates that this is the child process */
       dup2(commpipe[1], 1);   /* Replace stdin with the in side of the pipe */
       close(commpipe[0]);     /* Close unused side of pipe (out side) */
       /* Replace the child fork with a new process */
       if (execl
           (program, program,
            NULL) == -1) {
           LFATAL("exec_clean_program : execl %s failed", program);
           exit(-1);
       }
   }
   return;
   EFUNC; 
}

/* This thread does general housekeeping.
   For now it checks that there is enough diskspace free for
   the databases. If not it syncs the database, 
   closes them and freezes I/O. */
void *housekeeping_worker(void *arg)
{
    char *dbpath;
    int result;
    int count=0;

    while (1) {
        while ( count <= 6 ) {
           switch(count)
           {
               case 0:
                  dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
                  break;
               case 1:
                  dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
                  break;
               case 2:
                  dbpath = as_sprintf("%s/metadata.tcb", config->meta);
                  break;
               case 3:
                  if (NULL != config->blockdatabs) {
                       dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
                  } else {
                       dbpath = s_strdup(config->blockdata);
                  }
                  break;
               case 4:
                  dbpath = as_sprintf("%s/symlink.tch", config->symlink);
                  break;
               case 5:
                  dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
                  break;
               case 6:
                  dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
                  break;
               default:
                  break;
           }
           result=check_free_space(dbpath);
           switch(result)
           {
               case 1:
                 freeze_nospace(dbpath);
                 break;
               case 2:
                 exec_clean_program();
                 break;
               default:
                  break;
           }
           free(dbpath);
           count++;
           sleep(config->inspectdiskinterval);
       }
       count=0;
    }
    return NULL; 
}

void show_lock_status(int csocket)
{
   timeoutWrite(3, csocket,
      "---------------------\n",
      strlen
      ("---------------------\n"));
   timeoutWrite(3, csocket,
      "normally unset\n\n",
      strlen
      ("normally unset\n\n"));
   if ( 0 != try_global_lock()) {
      timeoutWrite(3, csocket,
      "global_lock : 1 (set)\n",
      strlen
      ("global_lock : 1 (set)\n"));
   } else {
      release_global_lock();
      timeoutWrite(3, csocket,
         "global_lock : 0 (not set)\n",
         strlen
         ("global_lock : 0 (not set)\n"));
   }
   if ( 0 != try_tiger_lock()) {
      timeoutWrite(3, csocket,
      "tiger_lock : 1 (set)\n",
      strlen
      ("tiger_lock : 1 (set)\n"));
   } else {
      release_tiger_lock();
      timeoutWrite(3, csocket,
         "tiger_lock : 0 (not set)\n",
         strlen
         ("tiger_lock : 0 (not set)\n"));
   }
   timeoutWrite(3, csocket,
      "---------------------\n",
      strlen
      ("---------------------\n"));
   timeoutWrite(3, csocket,
      "normally set\n\n",
      strlen
      ("normally set\n\n"));
}

void *ioctl_worker(void *arg)
{
    int msocket;
    int csocket;
    const char *port;
    const char *proto = "tcp";
    struct sockaddr_un client_address;
    socklen_t client_len;
    char buf[1028];
    char *addr;
    int err = 0;
    char *result;
    char *message = NULL;
    bool isfrozen = 0;

    msocket = -1;
    while (1) {
        addr = getenv("LISTEN_IP");
        port = getenv("LISTEN_PORT");
        if (NULL == port)
            port = "100";
        if (NULL == addr)
            LWARNING
                ("The administration session is not limited to localhost, this is not recommended.");
        msocket = serverinit(addr, port, proto);
        if (msocket != -1)
            break;
        sleep(1);
        close(msocket);
    }

    client_len = sizeof(client_address);
    while (1) {
        csocket =
            accept(msocket, (struct sockaddr *) &client_address,
                   &client_len);
        while (1) {
            result = NULL;
            if (-1 == timeoutWrite(3, csocket, ">", 1))
                break;
            if (-1 == readnlstring(10, csocket, buf, 1024)) {
                result = "timeout";
                err = 1;
                break;
            }
            if (0 == strncmp(buf, "\r", strlen("\r")))
                continue;
            if (0 == strncmp(buf, "quit\r", strlen("quit\r"))
                || 0 == strncmp(buf, "exit\r", strlen("exit\r"))) {
                err = 0;
                result = "bye";
                break;
            }
            if (0 == strncmp(buf, "freeze\r", strlen("freeze\r"))) {
                if (0 == isfrozen) {
                    result = "All i/o is now suspended.";
                    err = 0;
                    get_global_lock();
                    dbsync();
                    isfrozen = 1;
                } else {
                    result = "i/o is already suspended.";
                    err = 1;
                }
            }
            if (0 == strncmp(buf, "defrost\r", strlen("defrost\r"))) {
                if (1 == isfrozen) {
                    result = "Resuming i/o.";
                    err = 0;
                    release_global_lock();
                    isfrozen = 0;
                } else {
                    result = "i/o is not suspended.";
                    err = 1;
                }
            }
            if (0 == strncmp(buf, "defrag\r", strlen("defrag\r"))) {
                result = "Resuming i/o after defragmentation.";
                err = 1;
                if (-1 ==
                    timeoutWrite(3, csocket,
                                 "Suspending i/o for defragmentation\n",
                                 strlen
                                 ("Suspending i/o for defragmentation\n")))
                    break;
                err = 0;
                get_global_lock();
                tc_defrag();
                tc_close(1);
                tc_open(1,0);
                release_global_lock();
            }
            if (0 == strncmp(buf, "help\r", strlen("help\r"))
                || 0 == strncmp(buf, "h\r", strlen("h\r"))) {
                result =
                    "valid commands: defrag defrost freeze help lockstatus quit|exit";
                err = 0;
            }
            if (0 == strncmp(buf, "lockstatus\r", strlen("lockstatus\r"))) {
                show_lock_status(csocket);
                result = "lockstatus listed";
                err=0;
            } 
            if (NULL == result) {
                err = -1;
                result = "unknown command";
            }
            if (err == 0) {
                message = as_sprintf("+OK %s\n", result);
                if (-1 ==
                    timeoutWrite(3, csocket, message, strlen(message)))
                    break;
            } else {
                message = as_sprintf("-ERR %s\n", result);
                if (-1 ==
                    timeoutWrite(3, csocket, message, strlen(message)))
                    break;
            }
            free(message);
            message = NULL;
        }
        if (message)
            free(message);
        if (err == 0) {
            message = as_sprintf("+OK %s\n", result);
            timeoutWrite(3, csocket, message, strlen(message));
        } else {
            message = as_sprintf("-ERR %s\n", result);
            timeoutWrite(3, csocket, message, strlen(message));
        }
        free(message);
        message = NULL;
        close(csocket);
    }
    return NULL;
}


// Flush data every flushtime seconds.
void *lessfs_flush(void *arg)
{
    unsigned long long lastoffset=0;

    while (1) {
        sleep(config->flushtime);
        LDEBUG("lessfs_flush: flush_dta_queue");
        get_global_lock();
        while ( 0 != tctreernum(cachetree)) {
           LDEBUG("Waiting for %llu records to drain",tctreernum(cachetree));
           tiger_lock();
           flush_queue(0,0);
           release_tiger_lock();
           usleep(10000);
        }
        if ( config->transactions) lessfs_trans_stamp(); 
        if (NULL == config->blockdatabs) {
           if ( lastoffset != nextoffset) {
              LDEBUG("write nextoffset=%llu",nextoffset);
              bin_write_dbdata(dbu, config->nexthash, config->hashlen, (unsigned char *) &nextoffset,
                               sizeof(unsigned long long));
              lastoffset=nextoffset;
           }
        }
        sync_all_filesizes();
        if ( config->blockdatabs != NULL ) {
            if ( config->transactions ) if ( !tchdbtrancommit(dbdta)) die_dataerr("IO error, unable to commit dbdta transaction");
        } else {
            fsync(fdbdta);
            if ( config->transactions ) if ( !tcbdbtrancommit(freelist)) die_dataerr("IO error, unable to commit freelist transaction");
        }
        
        if ( config->transactions ) {
           if ( !tchdbtrancommit(dbu) ) die_dataerr("IO error, unable to commit blockusage transaction");
           if ( !tchdbtrancommit(dbb) ) die_dataerr("IO error, unable to commit fileblock transaction");
           if ( !tchdbtrancommit(dbp) ) die_dataerr("IO error, unable to commit metadata transaction");
           if ( !tchdbtrancommit(dbs) ) die_dataerr("IO error, unable to commit symlink transaction");
           if ( !tcbdbtrancommit(dbdirent)) die_dataerr("IO error, unable to commit dirent transaction");
           if ( !tcbdbtrancommit(dbl)) die_dataerr("IO error, unable to commit hardlink transaction");
        }
        /* Make sure that the meta data is updated every once in a while */
        tcbdbsync(dbdirent);
        tcbdbsync(dbl);
        tchdbsync(dbp);
        tchdbsync(dbs);
        if ( config->blockdatabs == NULL ) {
           tcbdbsync(freelist);
        }else tchdbsync(dbdta);
        tchdbsync(dbu);
        tchdbsync(dbb);

        if ( config->transactions ) {
           if ( config->blockdatabs != NULL ){
               tchdbtranbegin(dbdta);
           } else tcbdbtranbegin(freelist);
           tchdbtranbegin(dbu);
           tchdbtranbegin(dbb);
           tchdbtranbegin(dbp);
           tchdbtranbegin(dbs);
           tcbdbtranbegin(dbdirent);
           tcbdbtranbegin(dbl);
        }
        release_global_lock();
    }
    pthread_exit(NULL);
}

void *init_worker(void *arg)
{
    int count;
    int c;
#ifndef SHA3
    word64 res[max_threads][3];
#endif
    char *a;
    unsigned long long p;
    CCACHEDTA *ccachedta;
    INOBNO *inobno[max_threads];
    char *key;
    int size;
    int vsize;
    int lockres;
    int found[max_threads];
    char *dupkey;

    memcpy(&count, arg, sizeof(int)); // count is thread number.
    found[count]=0;
    key=s_malloc(sizeof(max_threads*sizeof(unsigned long long)));
    while (1) {
        if ( found[count] == 0 ) {
           sleep(1);
        } 
        found[count]=0;
        tiger_lock();
        tctreeiterinit(cachetree);
        if ( NULL != (key=(char *)tctreeiternext(cachetree, &size))){
           a=(char *)tctreeget(cachetree, (void *)key, size, &vsize);
           if ( NULL != a ) {
              memcpy(&p,a,vsize);
              ccachedta=(CCACHEDTA *)p;
              dupkey=s_malloc(size);
              memcpy(dupkey,key,size);
              inobno[count]=(INOBNO *)dupkey;
              tctreeout(cachetree,key,size);
              found[count]++;
              ccachedta->pending=1;
              release_tiger_lock();
              cook_cache(dupkey,size,ccachedta); 
              LDEBUG("Write %llu-%llu done get lock and delete cache",inobno[count]->inode,inobno[count]->blocknr);
              free(dupkey);
           } 
        }
        if ( 0 == found[count]) release_tiger_lock(); 
    }
    LFATAL("Thread %u exits",count);
    pthread_exit(NULL);
}

/* Write the hash for string LESSFS_DIRTY to DBU
   When this hash is present during mount the filesystem
   has not been unmounted cleanly previously.*/
void mark_dirty()
{
    unsigned char *stiger;
    char *brand;
    INUSE finuse;
    time_t thetime;
    unsigned long long inuse;
#ifndef SHA3
    word64 res[3];
#endif

    brand=as_sprintf("LESSFS_DIRTY");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    thetime = time(NULL);
    inuse=thetime;
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,inuse);
    } else {
        finuse.inuse=BLKSIZE;
        finuse.size=inuse;
        finuse.offset=0;
        file_update_inuse(stiger,&finuse);
    }
    free(brand);
#ifdef SHA3
    free(stiger);
#endif
    tchdbsync(dbu); 
    return;
}

/* Return 1 when filesystem is dirty */
int check_dirty()
{
    unsigned char *stiger;
    char *brand;
    unsigned long long inuse;
    INUSE *finuse;
    int dirty=0;
#ifndef SHA3
    word64 res[3];
#endif

    brand=as_sprintf("LESSFS_DIRTY");
#ifdef SHA3
    stiger=sha_binhash((unsigned char *)brand, strlen(brand));
#else
    binhash((unsigned char *)brand, strlen(brand), res);
    stiger=(unsigned char *)&res;
#endif
    if ( NULL == config->blockdatabs ) {
      finuse=file_get_inuse(stiger);
      if ( NULL != finuse ) {
         free(finuse);
         dirty=1;
      }
    } else {
      inuse=getInUse(stiger);
      if ( 0 != inuse ) dirty=1;
    }
#ifdef SHA3
    free(stiger);
#endif
    free(brand);
    return(dirty);
}

void check_blocksize()
{
    int blksize;

    blksize=get_blocksize();
    if ( blksize != BLKSIZE ) die_dataerr("Not allowed to mount lessfs with blocksize %u when previously used with blocksize %i",BLKSIZE,blksize);
    return;
}

static void *lessfs_init()
{
    unsigned int count = 0;
    unsigned int *cnt;
    unsigned long long ldate;
#ifndef SHA3
    word64 res[3]; 
#endif
    int ret;
    unsigned char *stiger;
    char *hashstr;
    INUSE *finuse;
    unsigned long long inuse;
    struct tm * timeinfo;
    time_t tdate;

#ifdef LZO
    initlzo();
#endif
    if (NULL != getenv("MAX_THREADS"))
        max_threads = atoi(getenv("MAX_THREADS"));

    pthread_t worker_thread[max_threads];
    pthread_t ioctl_thread;
    pthread_t housekeeping_thread;
    pthread_t flush_thread;
    pthread_t queue_gard_thread;

    for (count = 0; count < max_threads; count++) {
        cnt = s_malloc(sizeof(int));
        memcpy(cnt, &count, sizeof(int));
        ret =
            pthread_create(&(worker_thread[count]), NULL, init_worker,
                           (void *) cnt);
        if (ret != 0)
            die_syserr();
    }
    ret = pthread_create(&ioctl_thread, NULL, ioctl_worker, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&flush_thread, NULL, lessfs_flush, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret = pthread_create(&queue_gard_thread, NULL, queue_gard, (void *) NULL);
    if (ret != 0)
        die_syserr();
    ret =
        pthread_create(&housekeeping_thread, NULL, housekeeping_worker,
                       (void *)NULL);
    if (ret != 0)
        die_syserr();

    check_blocksize();
#ifdef SHA3
    hashstr=as_sprintf("BMW%i",config->hashlen);
    stiger=sha_binhash((unsigned char *)hashstr, strlen(hashstr));
#else
    hashstr=as_sprintf("TGR%i",config->hashlen);
    binhash((unsigned char *)hashstr, strlen(hashstr), res);
    stiger=(unsigned char *)&res;
#endif
    if ( NULL == config->blockdatabs ) {
       if ( NULL == (finuse=file_get_inuse(stiger)))  {
           die_dataerr("Invalid hashsize or hash found, do not change hash or hashsize after formatting lessfs.");
       } else free(finuse);
    } else {
       if ( 0 == getInUse(stiger))
           die_dataerr("Invalid hashsize or hash found, do not change hash or hashsize after formatting lessfs.");
    }
    free(hashstr);
#ifdef SHA3
    free(stiger);
#endif


    if ( config->transactions ) {
#ifdef SHA3
       config->commithash=sha_binhash((unsigned char *)"COMMITSTAMP", strlen("COMMITSTAMP"));
#else
       binhash((unsigned char *)"COMMITSTAMP", strlen("COMMITSTAMP"), res);
       config->commithash=s_malloc(config->hashlen);
       memcpy(config->commithash,(unsigned char *)&res,config->hashlen);
#endif

       if ( config->blockdatabs != NULL ) {
           inuse=getInUse(config->commithash);
           if ( 0 == inuse ) { 
              LFATAL("COMMITSTAMP not found");
              lessfs_trans_stamp(); 
              inuse=getInUse(config->commithash);
           }
           ldate=inuse;
       } else {
           finuse=file_get_inuse(config->commithash);
           if ( NULL == finuse ) {
               LFATAL("COMMITSTAMP not found, upgrading the filesystem to support transactions");
               lessfs_trans_stamp();
               finuse=file_get_inuse(config->commithash);
           }
           ldate=finuse->inuse;
       }
       tdate=ldate;
       timeinfo = localtime ( &tdate );
    }

    if ( check_dirty()){
       LINFO("Lessfs has not been unmounted cleanly.");
       if ( config->transactions ) {
          LINFO("Rollback to : %s",asctime(timeinfo));
       } else LINFO("Lessfs has not been unmounted cleanly, you are advised to run lessfsck.");
    } else {
       LINFO("The filesystem is clean.");
       if ( config->transactions ) {
          LINFO("Last used at : %s",asctime(timeinfo));
       }
       mark_dirty();
    }
    return NULL;
}

static struct fuse_operations lessfs_oper = {
    .getattr = lessfs_getattr,
    .access = lessfs_access,
    .readlink = lessfs_readlink,
    .readdir = lessfs_readdir,
    .mknod = lessfs_mknod,
    .mkdir = lessfs_mkdir,
    .symlink = lessfs_symlink,
    .unlink = lessfs_unlink,
    .rmdir = lessfs_rmdir,
    .rename = lessfs_rename,
    .link = lessfs_link,
    .chmod = lessfs_chmod,
    .chown = lessfs_chown,
    .truncate = lessfs_truncate,
    .utimens = lessfs_utimens,
    .open = lessfs_open,
    .read = lessfs_read,
    .write = lessfs_write,
    .statfs = lessfs_statfs,
    .release = lessfs_release,
    .fsync = lessfs_fsync,
    .destroy = lessfs_destroy,
    .init = lessfs_init,
};

void usage(char *appName)
{
    char **argv = (char **) malloc(2 * sizeof(char *));
    argv[0] = appName;
    argv[1] = (char *) malloc(3 * sizeof(char));
    memcpy(argv[1], "-h\0", 3);
    fuse_main(2, argv, &lessfs_oper, NULL);
    FUNC;
    printf("\n"
           "-------------------------------------------------------\n"
           "lessfs %s\n"
           "\n"
           "Usage: %s [/path_to_config.cfg] [mount_point] <FUSE OPTIONS>\n"
           "\n"
           "Example :\nmklessfs /etc/lessfs.cfg \nlessfs   /etc/lessfs.cfg /mnt\n\n"
           "A high performance example with big_writes.\n(Requires kernel 2.6.26 or higher and a recent version of fuse.)\n"
           "lessfs /etc/lessfs.cfg /fuse -o use_ino,readdir_ino,default_permissions,\\\n       allow_other,big_writes,max_read=131072,max_write=131072\n"
           "-------------------------------------------------------\n",
           VERSION, appName);
    exit(EXIT_USAGE);
}

int verify_kernel_version()
{
    struct utsname un;
    char *begin;
    char *end;
    int count;

    uname(&un);
    begin = un.release;

    for (count = 0; count < 3; count++) {
        end = strchr(begin, '.');
        if (NULL != end) {
            end[0] = 0;
            end++;
        }
        if (count == 0 && atoi(begin) < 2)
            return (-1);
        if (count == 0 && atoi(begin) > 2)
            break;
        if (count == 1 && atoi(begin) < 6)
            return (-2);
        if (count == 1 && atoi(begin) > 6)
            break;
        if (count == 2 && atoi(begin) < 26)
            return (-3);
        begin = end;
    }
    return (0);
}

int main(int argc, char *argv[])
{
    int res;
    char *p, *maxwrite, *maxread;
    char **argv_new = (char **) malloc(argc * sizeof(char *));
    int argc_new = argc - 1;
    struct rlimit lessfslimit;

    FUNC;
    if ((argc > 1) && (strcmp(argv[1], "-h") == 0)) {
        usage(argv[0]);
    }

    if (argc < 3) {
        usage(argv[0]);
    }

    if (-1 == r_env_cfg(argv[1]))
        usage(argv[0]);
    argv_new[0] = argv[0];
    int i;
    for (i = 1; i < argc - 1; i++) {
        argv_new[i] = argv[i + 1];
        if (NULL != strstr(argv[i + 1], "big_writes")) {
            maxwrite = strstr(argv[i + 1], "max_write=");
            maxread = strstr(argv[i + 1], "max_read=");
            if (NULL != maxwrite && NULL != maxread) {
                p = strchr(maxwrite, '=');
                p++;
                BLKSIZE = atoi(p);
                p = strchr(maxread, '=');
                p++;
                if (atoi(p) != BLKSIZE) {
                    LFATAL
                        ("lessfs : Supplied values for max_read and max_write must match.");
                    fprintf(stderr,
                            "Supplied values for max_read and max_write must match.\n");
                    exit(EXIT_SYSTEM);
                }
                if (BLKSIZE > 4096 && 0 != verify_kernel_version()) {
                    LFATAL
                        ("The kernel used is to old for larger then 4k blocksizes, kernel >= 2.6.26 is required.");
                    exit(EXIT_SYSTEM);
                }
            } else {
                LFATAL
                    ("lessfs : big_writes specified without max_write or max_read.");
                fprintf(stderr,
                        "big_writes specified without max_write or max_read.\n");
                exit(EXIT_SYSTEM);
            }
        }
    }
// Enable dumping of core for debugging.
    if (NULL != getenv("COREDUMPSIZE")) {
        lessfslimit.rlim_cur = lessfslimit.rlim_max =
            atoi(getenv("COREDUMPSIZE"));
        if (0 != setrlimit(RLIMIT_CORE, &lessfslimit)) {
            fprintf(stderr, "Failed to set COREDUMPSIZE to %i : error %s",
                    atoi(getenv("COREDUMPSIZE")), strerror(errno));
            exit(EXIT_SYSTEM);
        }
    } else {
        signal(SIGSEGV, segvExit);
    }
    LDEBUG("lessfs : blocksize is set to %u", BLKSIZE);
    signal(SIGHUP, normalExit);
    signal(SIGTERM, normalExit);
    signal(SIGALRM, normalExit);
    signal(SIGINT, normalExit);
    signal(SIGUSR1, libSafeExit);
    if (NULL != getenv("DEBUG"))
        debug = atoi(getenv("DEBUG"));
    parseconfig(0);

    struct fuse_args args = FUSE_ARGS_INIT(argc_new, argv_new);
    fuse_opt_parse(&args, NULL, NULL, NULL);
    p=getenv("BLKSIZE");
    if ( NULL != p ) { 
       BLKSIZE=atoi(p);
       if(BLKSIZE > 131072) {
              LFATAL
                 ("Fuse does not support a blocksize greater then 131072 bytes.");
              fprintf(stderr,"Fuse does not support a blocksize greater then 131072 bytes.\n");
              exit(EXIT_SYSTEM);
       }
       p=as_sprintf("-omax_write=%u,max_read=%u",BLKSIZE,BLKSIZE);
       fuse_opt_add_arg(&args, p);
       free(p);
       if ( BLKSIZE > 4096 ) {
           if ( 0 != verify_kernel_version()) {
              LFATAL
                 ("The kernel used is to old for larger then 4k blocksizes, kernel >= 2.6.26 is required.");
              exit(EXIT_SYSTEM);
           }
           fuse_opt_add_arg(&args, "-obig_writes");
       }
       fuse_opt_add_arg(&args, "-ohard_remove,negative_timeout=0,entry_timeout=0,attr_timeout=0,use_ino,readdir_ino,default_permissions,allow_other");
    }
    return fuse_main(args.argc, args.argv, &lessfs_oper, NULL);
    free(argv_new);
    return (res);
}
