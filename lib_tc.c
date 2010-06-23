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

#include <tcutil.h>
#include <tcbdb.h>
#include <tchdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <aio.h>
#include <mhash.h>
#include <mutils/mhash.h>
#include <sys/time.h>

#include "lib_safe.h"
#include "lib_cfg.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#endif
#include "lib_qlz.h"
#include "lib_tc.h"
#include "lib_crypto.h"
#include "file_io.h"

extern char *logname;
extern char *function;
extern int debug;
extern int BLKSIZE;
extern int max_threads;
extern char *passwd;

TCHDB *dbb = NULL;
TCHDB *dbu = NULL;
TCHDB *dbp = NULL;
TCBDB *dbl = NULL;              // Hardlink
TCHDB *dbs = NULL;              // Symlink
TCHDB *dbdta = NULL;
TCBDB *dbdirent = NULL;
TCBDB *freelist = NULL;         // Free list for file_io

TCTREE *workqtree;
TCTREE *delayedqtree;
TCTREE *readcachetree;

TCTREE *metatree;
TCTREE *hashtree;
int fdbdta = 0;

unsigned long long nextoffset = 0;
int written = 0;

static pthread_mutex_t global_lock_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t meta_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t offset_mutex = PTHREAD_MUTEX_INITIALIZER;
const char *write_lockedby;
const char *global_lockedby;
const char *meta_lockedby;
const char *hash_lockedby;
const char *offset_lockedby;

u_int32_t db_flags, env_flags;

#define die_dberr(f...) { LFATAL(f); exit(EXIT_DBERR); }
#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }
#define die_syserr() { LFATAL("Fatal system error : %s",strerror(errno)); exit(EXIT_SYSTEM); }

unsigned char *thash(unsigned char *buf, int size, int thread_number)
{
    MHASH td[MAX_ALLOWED_THREADS];
    unsigned char *hash[thread_number];

    td[thread_number] = mhash_init(config->selected_hash);
    if (td[thread_number] == MHASH_FAILED) exit(1);

    mhash(td[thread_number], buf, size);
    hash[thread_number] = mhash_end(td[thread_number]);
    return hash[thread_number];
}

void logiv(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;

    for (n = 0; n < 8; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LDEBUG("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}


#ifdef DEBUG
void loghash(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;

    for (n = 0; n < config->hashlen ; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LDEBUG("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}
# else
void loghash(char *msg, unsigned char *bhash)
{
}
# endif


void log_fatal_hash(char *msg, unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1, *p2;

    for (n = 0; n < config->hashlen ; n++) {
        p1 = as_sprintf("%02X", bhash[n]);
        if (n == 0) {
            ascii_hash = s_strdup(p1);
        } else {
            p2 = s_strdup(ascii_hash);
            free(ascii_hash);
            ascii_hash = as_sprintf("%s%s", p2, p1);
            free(p2);
        }
        free(p1);
    }
    LFATAL("%s : %s", msg, ascii_hash);
    free(ascii_hash);
}

TCHDB *hashdb_open(char *dbpath, int cacherow,
                   unsigned long long bucketsize)
{
    TCHDB *hdb;
    int ecode;

    FUNC;
    hdb = tchdbnew();
    if (cacherow > 0) {
        tchdbsetcache(hdb, cacherow);
    }

    if (config->defrag == 1) {
        if (!tchdbsetdfunit(hdb, 1)) {
            ecode = tchdbecode(hdb);
            die_dberr("Error on setting defragmentation : %s",tchdberrmsg(ecode));
        }
    }
    tchdbsetmutex(hdb);
    tchdbtune(hdb, bucketsize, 0, 0, HDBTLARGE);
    //if (!tchdbopen(hdb, dbpath, HDBOWRITER | HDBOCREAT| HDBOTSYNC)) {
    if (!tchdbopen(hdb, dbpath, HDBOWRITER | HDBOCREAT)) {
        ecode = tchdbecode(hdb);
        fprintf(stderr,"Error while opening database : %s : %s\n", dbpath, tchdberrmsg(ecode));
        die_dberr("open error: %s", tchdberrmsg(ecode));
    }
    EFUNC;
    return hdb;
}

void tc_defrag()
{
    start_flush_commit();
    write_lock((char *)__PRETTY_FUNCTION__);
    if (!tchdboptimize(dbb, atol(config->fileblockbs), 0, 0, HDBTLARGE))
        LINFO("fileblock.tch not optimized");
    if (!tchdboptimize(dbu, atol(config->blockusagebs), 0, 0, HDBTLARGE))
        LINFO("blockusage.tch not optimized");
    if (!tchdboptimize(dbp, atol(config->metabs), 0, 0, HDBTLARGE))
        LINFO("metadata.tcb not optimized");
    if (!tchdboptimize(dbs, atol(config->symlinkbs), 0, 0, HDBTLARGE))
        LINFO("symlink.tch not optimized");
    if (NULL != config->blockdatabs) {
        if (!tchdboptimize
            (dbdta, atol(config->blockdatabs), 0, 0, HDBTLARGE))
            LINFO("blockdata.tch not optimized");
    } else {
        if (!tcbdboptimize(freelist, 0, 0, atol(config->freelistbs), -1, -1, BDBTLARGE))
            LINFO("freelist.tcb not optimized");
    }
    if (!tcbdboptimize
        (dbdirent, 0, 0, atol(config->direntbs), -1, -1, BDBTLARGE))
        LINFO("dirent.tcb not optimized");
    if (!tcbdboptimize
        (dbl, 0, 0, atol(config->hardlinkbs), -1, -1, BDBTLARGE))
        LINFO("hardlink.tcb not optimized");
    end_flush_commit();
    release_write_lock();
}

void check_datafile_sanity()
{
    struct stat stbuf;
    unsigned long long rsize;

    if (-1 == stat(config->blockdata, &stbuf) ) 
        die_dataerr("Failed to stat %s\n",config->blockdata);
    if ( stbuf.st_size > nextoffset ) {
       LDEBUG("nextoffset = %llu, real size = %llu",nextoffset,stbuf.st_size);
       rsize=round_512(nextoffset);
       if ( -1 == ftruncate(fdbdta, rsize)) die_dataerr("Failed to truncate %s to %llu bytes\n",config->blockdata,rsize);
    }
}

void tc_open(bool defrag, bool createpath)
{
    char *dbpath;
    int ecode;
    struct stat stbuf;
    char *sp;
    char *hashstr;
    DBT *data;


    FUNC;
    dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
    if ( createpath ) mkpath(config->fileblock,0744);
    LDEBUG("Open database %s", dbpath);
    dbb = hashdb_open(dbpath, 2621440, atol(config->fileblockbs));
    free(dbpath);

    dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
    if ( createpath ) mkpath(config->blockusage,0744);
    LDEBUG("Open database %s", dbpath);
    dbu = hashdb_open(dbpath, 2621440, atol(config->blockusagebs));
    free(dbpath);

    dbpath = as_sprintf("%s/metadata.tcb", config->meta);
    if ( createpath ) mkpath(config->meta,0744);
    LDEBUG("Open database %s", dbpath);
    dbp = hashdb_open(dbpath, 1000, atol(config->metabs));
    free(dbpath);

    if (NULL != config->blockdatabs) {
        dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
        if ( createpath ) mkpath(config->blockdata,0744);
        LDEBUG("Open database %s", dbpath);
        dbdta = hashdb_open(dbpath, 10, atol(config->blockdatabs));
        free(dbpath);
    } else {
        sp=s_dirname(config->blockdata);
        if ( createpath ) mkpath(sp,0744);
        free(sp);
        freelist = tcbdbnew();
        tcbdbsetmutex(freelist); 
        tcbdbtune(freelist, 0, 0, atol(config->freelistbs), -1, -1,
                  BDBTLARGE);
        /* The dirent database is a B-TREE DB with cursors */
        dbpath = as_sprintf("%s/freelist.tcb", config->freelist);
        if ( createpath ) mkpath(config->freelist,0744);
        if (config->defrag == 1) {
            if (!tcbdbsetdfunit(freelist, 1)) {
                ecode = tcbdbecode(freelist);
                die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
            }
        }
        LDEBUG("Open database %s", dbpath);
        //if (!tcbdbopen(freelist, dbpath, BDBOWRITER | BDBOCREAT|BDBOTSYNC)) {
        if (!tcbdbopen(freelist, dbpath, BDBOWRITER | BDBOCREAT)) {
            ecode = tcbdbecode(freelist);
            die_dberr("open error: %s", tcbdberrmsg(ecode));
        }
        free(dbpath);
    }

    dbpath = as_sprintf("%s/symlink.tch", config->symlink);
    if ( createpath ) mkpath(config->symlink,0744);
    LDEBUG("Open database %s", dbpath);
    dbs = hashdb_open(dbpath, 10, atol(config->symlinkbs));
    free(dbpath);
    dbdirent = tcbdbnew();
    tcbdbsetmutex(dbdirent);
    tcbdbtune(dbdirent, 0, 0, atol(config->direntbs), -1, -1, BDBTLARGE);
    /* The dirent database is a B-TREE DB with cursors */
    dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
    if ( createpath ) mkpath(config->dirent,0744);
    if (config->defrag == 1) {
        if (!tcbdbsetdfunit(dbdirent, 1)) {
            ecode = tcbdbecode(dbdirent);
            die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
        }
    }
    LDEBUG("Open database %s", dbpath);
    if (!tcbdbopen(dbdirent, dbpath, BDBOWRITER | BDBOCREAT|BDBOTSYNC)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("open error: %s", tcbdberrmsg(ecode));
    }
    free(dbpath);

    dbl = tcbdbnew();
    tcbdbsetmutex(dbl);
    tcbdbtune(dbl, 0, 0, atol(config->hardlinkbs), -1, -1, BDBTLARGE);
    /* The dbl database is a B-TREE DB with cursors */
    dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
    if ( createpath ) mkpath(config->hardlink,0744);
    LDEBUG("Open database %s", dbpath);

    if (config->defrag == 1) {
        if (!tcbdbsetdfunit(dbl, 1)) {
            ecode = tcbdbecode(dbl);
            die_dberr("set defrag error: %s", tcbdberrmsg(ecode));
        }
    }
    if (!tcbdbopen(dbl, dbpath, BDBOWRITER | BDBOCREAT|BDBOTSYNC)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("open error: %s", tcbdberrmsg(ecode));
    }
    free(dbpath);

    if (!defrag) {
        workqtree=tctreenew();
        readcachetree=tctreenew();
        hashtree=tctreenew();
        delayedqtree=tctreenew();
        metatree=tctreenew();
        if (NULL == config->blockdatabs) {
            if (-1 ==
                (fdbdta =
                 s_open2(config->blockdata, O_CREAT | O_RDWR, S_IRWXU)))
                die_syserr();
            if (-1 == (stat(config->blockdata, &stbuf)))
                die_syserr();
            hashstr=as_sprintf("NEXTOFFSET");
            config->nexthash=(char *)thash((unsigned char *)hashstr, strlen(hashstr),MAX_ALLOWED_THREADS);
            data = search_dbdata(dbu, config->nexthash, config->hashlen);
            if ( NULL == data ) { 
                 LFATAL("Filesystem upgraded to support transactions");
                 nextoffset=stbuf.st_size;
            } else {
                 memcpy(&nextoffset,data->data,sizeof(unsigned long long));
                 DBTfree(data);
            }
            if ( config->transactions ) {
                check_datafile_sanity();
            }
        }
    }
    LDEBUG("All databases are open");
    if ( config->transactions ) {
       if (NULL != config->blockdatabs) {
           tchdbtranbegin(dbdta);
       } else tcbdbtranbegin(freelist);
       tchdbtranbegin(dbu);
       tchdbtranbegin(dbb);
       tchdbtranbegin(dbs);
       tchdbtranbegin(dbp);
       tcbdbtranbegin(dbdirent);
       tcbdbtranbegin(dbl);
    }
    EFUNC;
}

void hashdb_close(TCHDB * hdb)
{
    int ecode;

    FUNC;
    /* close the database */
    if (!tchdbclose(hdb)) {
        ecode = tchdbecode(hdb);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tchdbdel(hdb);
}

void tc_close(bool defrag)
{
    int ecode;

    FUNC;

    if (NULL == config->blockdatabs) {
        bin_write_dbdata(dbu, config->nexthash, config->hashlen, (unsigned char *) &nextoffset,
                         sizeof(unsigned long long));
    }
    if ( config->transactions ) {
       if (NULL != config->blockdatabs) {
          if ( !tchdbtrancommit(dbdta)) die_dataerr("IO error, unable to commit blockdata transaction");
       } else if ( !tcbdbtrancommit(freelist)) die_dataerr("IO error, unable to commit freelist transaction");
       if ( !tchdbtrancommit(dbu)) die_dataerr("IO error, unable to commit blockusage transaction");
       if ( !tchdbtrancommit(dbb)) die_dataerr("IO error, unable to commit fileblock transaction");
       if ( !tchdbtrancommit(dbp)) die_dataerr("IO error, unable to commit metadata transaction");
       if ( !tchdbtrancommit(dbs)) die_dataerr("IO error, unable to commit symlink transaction");
       if ( !tcbdbtrancommit(dbdirent)) die_dataerr("IO error, unable to commit dbdirent transaction");
       if ( !tcbdbtrancommit(dbl)) die_dataerr("IO error, unable to commit hardlink transaction");
    }
    hashdb_close(dbb);
    hashdb_close(dbp);
    hashdb_close(dbu);
    hashdb_close(dbs);
    if (NULL != config->blockdatabs) {
        hashdb_close(dbdta);
    } else {
       /* close the B-TREE database */
       if (!tcbdbclose(freelist)) {
           ecode = tcbdbecode(freelist);
           die_dberr("close error: %s", tchdberrmsg(ecode));
       }
       /* delete the object */
       tcbdbdel(freelist);
    }

    /* close the B-TREE database */
    if (!tcbdbclose(dbdirent)) {
        ecode = tcbdbecode(dbdirent);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tcbdbdel(dbdirent);

    /* close the B-TREE database */
    if (!tcbdbclose(dbl)) {
        ecode = tcbdbecode(dbl);
        die_dberr("close error: %s", tchdberrmsg(ecode));
    }
    /* delete the object */
    tcbdbdel(dbl);

    if (!defrag) {
        tctreeclear(workqtree);
        tctreeclear(readcachetree);
        tctreeclear(hashtree);
        tctreeclear(delayedqtree);
        tctreeclear(metatree);
        if (NULL == config->blockdatabs) {
            close(fdbdta);
            free(config->nexthash);
        }
    }
    EFUNC;
}

void die_lock_report(const char *msg, const char *msg2)
{
    LFATAL("die_lock_report : timeout on %s, called by %s",msg2,msg);
    if ( 0 == try_global_lock() ) {
       LFATAL("global_lock : 0 (unset)"); 
    } else {
       LFATAL("global_lock : 1 (set)");
    }
    if ( 0 == try_write_lock() ) {
       LFATAL("write_lock : 0 (unset)");
    } else {
       LFATAL("write_lock : 1 (set)");
    }
    if ( 0 == try_meta_lock() ) {
       LFATAL("meta_lock : 0 (unset)");
    } else {
       LFATAL("meta_lock : 1 (set)");
    }
    if ( 0 == try_hash_lock() ) {
       LFATAL("hash_lock : 0 (unset)");
    } else {
       LFATAL("hash_lock : 1 (set)");
    }
    die_dataerr("Abort after deadlock");
}

void get_global_lock(const char *msg)
{
    FUNC;
#ifdef DBGLOCK
    struct timespec deltatime;
    deltatime.tv_sec = time(NULL)+GLOBAL_LOCK_TIMEOUT;
    deltatime.tv_nsec = 0;
    int err_code;

    err_code = pthread_mutex_timedlock(&global_lock_mutex, &deltatime );
    if (err_code != 0) {
       die_lock_report(msg, __PRETTY_FUNCTION__);
    }
#else
    pthread_mutex_lock(&global_lock_mutex);
#endif
    global_lockedby=msg;
    EFUNC;
    return;
}

void get_offset_lock(const char *msg)
{
    FUNC;
#ifdef DBGLOCK
    struct timespec deltatime;
    deltatime.tv_sec = time(NULL)+GLOBAL_LOCK_TIMEOUT;
    deltatime.tv_nsec = 0;
    int err_code;

    err_code = pthread_mutex_timedlock(&offset_mutex, &deltatime );
    if (err_code != 0) {
       die_lock_report(msg, __PRETTY_FUNCTION__);
    }
#else
    pthread_mutex_lock(&offset_mutex);

#endif
    offset_lockedby=msg;
    EFUNC;
    return;
}

void meta_lock(const char *msg)
{
    FUNC;
#ifdef DBGLOCK
    struct timespec deltatime;
    deltatime.tv_sec = time(NULL)+LOCK_TIMEOUT;
    deltatime.tv_nsec = 0;
    int err_code;

    FUNC;
    err_code = pthread_mutex_timedlock(&meta_mutex, &deltatime );
    if (err_code != 0) {
       die_lock_report(msg, __PRETTY_FUNCTION__);
    }
#else
    pthread_mutex_lock(&meta_mutex);
#endif
    meta_lockedby=msg;
    EFUNC;
    return;
}



void get_hash_lock(const char *msg)
{
    FUNC;
#ifdef DBGLOCK
    struct timespec deltatime;
    deltatime.tv_sec = time(NULL)+LOCK_TIMEOUT;
    deltatime.tv_nsec = 0;
    int err_code;

    FUNC;
    err_code = pthread_mutex_timedlock(&hash_mutex, &deltatime );
    if (err_code != 0) {
       die_lock_report(msg, __PRETTY_FUNCTION__);
    }
#else
    pthread_mutex_lock(&hash_mutex);
#endif
    hash_lockedby=msg;
    EFUNC;
    return;
}

void write_lock(const char *msg)
{
    FUNC;
#ifdef DBGLOCK
    struct timespec deltatime;
    deltatime.tv_sec = time(NULL)+LOCK_TIMEOUT;
    deltatime.tv_nsec = 0;
    int err_code;
    

    err_code = pthread_mutex_timedlock(&write_mutex, &deltatime );
    if (err_code != 0) {
       die_lock_report(msg, __PRETTY_FUNCTION__);
    }
#else
    pthread_mutex_lock(&write_mutex);
#endif
    write_lockedby=msg;
    EFUNC;
    return;
}

void release_write_lock()
{
    FUNC;
    pthread_mutex_unlock(&write_mutex);
    EFUNC;
    return;
}

void release_meta_lock()
{
    FUNC;
    pthread_mutex_unlock(&meta_mutex);
    EFUNC;
    return;
}

void release_hash_lock()
{
    FUNC;
    pthread_mutex_unlock(&hash_mutex);
    EFUNC;
    return;
}

void release_global_lock()
{
    FUNC;
    pthread_mutex_unlock(&global_lock_mutex);
    EFUNC;
    return;
}

void release_offset_lock()
{
    FUNC;
    pthread_mutex_unlock(&offset_mutex);
    EFUNC;
    return;
}

int try_write_lock()
{
    int res;
    res = pthread_mutex_trylock(&write_mutex);
    return (res);
}

int try_meta_lock()
{
    int res;
    res = pthread_mutex_trylock(&meta_mutex);
    return (res);
}

int try_hash_lock()
{
    int res;
    res = pthread_mutex_trylock(&hash_mutex);
    return (res);
}

int try_global_lock()
{
    int res;
    FUNC;
    res = pthread_mutex_trylock(&global_lock_mutex);
    EFUNC;
    return (res);
}

DBT *create_ddbuf(struct stat stbuf, char *filename, unsigned long long real_size)
{
    DBT *ddbuf;
    int len;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif

    FUNC;
    if (NULL != filename) {
        len = sizeof(struct stat)+sizeof(unsigned long long) + strlen((char *) filename) + 1;
    } else
        len = sizeof(struct stat)+sizeof(unsigned long long) + 1;

    ddbuf = s_malloc(sizeof(DBT));
    ddbuf->size = len;
    ddbuf->data = s_zmalloc(ddbuf->size);
    memcpy(ddbuf->data, &stbuf, sizeof(struct stat));
    memcpy(ddbuf->data+sizeof(struct stat), &real_size, sizeof(unsigned long long));
    if (NULL != filename) {
        memcpy(ddbuf->data + sizeof(struct stat)+sizeof(unsigned long long), (char *) filename,
               strlen((char *) filename) + 1);
    }

#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        encrypted = encrypt(ddbuf->data, ddbuf->size);
        DBTfree(ddbuf);
        EFUNC;
        return encrypted;
    }
#endif
    EFUNC;
    return ddbuf;
}

DBT *create_mem_ddbuf(MEMDDSTAT * ddstat)
{
    DBT *ddbuf;

    ddbuf = s_malloc(sizeof(DBT));
    ddbuf->data = s_malloc(sizeof(MEMDDSTAT));
    ddbuf->size = sizeof(MEMDDSTAT);
    memcpy(ddbuf->data, ddstat, sizeof(MEMDDSTAT));
    return ddbuf;
}

DDSTAT *value_to_ddstat(DBT * vddstat)
{
    DDSTAT *ddbuf;
    int filelen;
    DBT *decrypted;

    FUNC;
    decrypted = vddstat;
#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        decrypted = decrypt(vddstat);
    }
#endif
    filelen = decrypted->size - (sizeof(struct stat)+sizeof(unsigned long long));
    ddbuf = s_malloc(sizeof(DDSTAT));
    memcpy(&ddbuf->stbuf, decrypted->data, sizeof(struct stat));
    memcpy(&ddbuf->real_size, decrypted->data+sizeof(struct stat), sizeof(unsigned long long));
    if (1 == filelen) {
        memset(&ddbuf->filename, 0, MAX_POSIX_FILENAME_LEN);
    } else {
        memcpy(ddbuf->filename, &decrypted->data[(sizeof(struct stat)+sizeof(unsigned long long))],
               filelen + 1);
    }
    LDEBUG("value_to_ddstat : return %llu", ddbuf->stbuf.st_ino);
#ifdef ENABLE_CRYPTO
    if (config->encryptmeta && config->encryptdata) {
        DBTfree(decrypted);
    }
#endif
    EFUNC;
    return ddbuf;
}

void dbmknod(const char *path, mode_t mode, char *linkdest, dev_t rdev)
{
    unsigned long long inode;

    FUNC;
    LDEBUG("dbmknod : %s", path);
    inode = get_next_inode();
    write_file_ent(path, inode, mode, linkdest, rdev);
    EFUNC;
    return;
}

void write_file_ent(const char *filename, unsigned long long inode,
                    mode_t mode, char *linkdest, dev_t rdev)
{
    struct stat stbuf;
    struct stat dirstat;
    time_t thetime;
    char *bname;
    char *parentdir;
    int res = 0;
    DBT *ddbuf;
    bool isdot = 0;
    bool isrootdir = 0;

    FUNC;
    LDEBUG("write_file_ent : filename %s, inodenumber %llu", filename,
           inode);
    bname = s_basename((char *) filename);
    parentdir = s_dirname((char *) filename);
    if (0 == strcmp(filename, "/"))
        isrootdir = 1;
    LDEBUG("write_file_ent: parentdir = %s", parentdir);
    write_nfi(inode + 1);

//Write stat structure to create an empty file.
    stbuf.st_ino = inode;
    stbuf.st_dev = 999988;
    stbuf.st_mode = mode;
    if (S_ISDIR(mode)) {
      stbuf.st_nlink = 2;
    } else stbuf.st_nlink = 1;
    if (!isrootdir) {
        if ( 0 == strcmp(filename,"/lost+found") ||\
             0 == strcmp(filename,"/.lessfs")||\
             0 == strcmp(filename,"/.lessfs/lessfs_stats")){
           stbuf.st_uid = 0;
           stbuf.st_gid = 0;
        } else {
           stbuf.st_uid = fuse_get_context()->uid;
           stbuf.st_gid = fuse_get_context()->gid;
        }
    } else {
        stbuf.st_uid = 0;
        stbuf.st_gid = 0;
    }
    stbuf.st_rdev = rdev;
    if (S_ISDIR(mode)) {
        stbuf.st_size = 4096;
        stbuf.st_blocks = 1;
    } else {
        stbuf.st_size = 0;
        stbuf.st_blocks = 0;
    }
    if (S_ISLNK(mode)) {
        stbuf.st_size = 3;
        stbuf.st_blocks = 1;
    }
    stbuf.st_blksize = BLKSIZE;
    thetime = time(NULL);
    stbuf.st_atim.tv_sec = thetime;
    stbuf.st_atim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;

    ddbuf = create_ddbuf(stbuf, bname, 0);
    LDEBUG("write_file_ent : write dbp inode %llu", inode);
    bin_write_dbdata(dbp, &inode, sizeof(inode), ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
    if (NULL != linkdest) {
        bin_write_dbdata(dbs, &inode, sizeof(unsigned long long), linkdest,
                         strlen(linkdest));
    }
    if (0 == strcmp(bname, "."))
        isdot = 1;
    if (0 == strcmp(bname, ".."))
        isdot = 1;
  recurse:
    if (S_ISDIR(mode) && isdot != 1) {
        btbin_write_dup(dbdirent, &stbuf.st_ino, sizeof(stbuf.st_ino),
                        &inode, sizeof(inode));
    } else {
        res = dbstat(parentdir, &dirstat);
        btbin_write_dup(dbdirent, &dirstat.st_ino, sizeof(dirstat.st_ino),
                        &inode, sizeof(inode));
    }
    if (S_ISDIR(mode) && !isdot && !isrootdir) {
        // Create the link inode to the previous directory
        LDEBUG("Create the link inode to the previous directory");
        isdot = 1;
        // Only if !isrootdir. Nothing lower the root.
        goto recurse;
    }
    free(parentdir);
    free(bname);
    EFUNC;
}

void write_nfi(unsigned long long nextinode)
{
    bin_write_dbdata(dbp, (unsigned char *) "NFI", strlen("NFI"),
                     (unsigned char *) &nextinode, sizeof(nextinode));
    return;
}

void formatfs()
{
    struct stat stbuf;
    unsigned long long nextinode = 0;
    unsigned char *stiger;
    char *blockdatadir;
#ifdef ENABLE_CRYPTO
    CRYPTO crypto;
#endif
    char *hashstr;
    INUSE inuse;

    FUNC;
    if (NULL == dbp) {
        tc_open(0,0);
    }
    hashstr=as_sprintf("%s%i",config->hash,config->hashlen);
    stiger=thash((unsigned char *)hashstr, strlen(hashstr), MAX_ALLOWED_THREADS);
    free(hashstr);
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,1);
    } else {
        inuse.inuse=1;
        inuse.size=0;
        inuse.offset=0;
        file_update_inuse(stiger,&inuse);
    }
    lessfs_trans_stamp();
    free(stiger);
    
#ifdef ENABLE_CRYPTO
    if (config->encryptdata) {
        stiger=thash(config->passwd, strlen((char *) config->passwd),MAX_ALLOWED_THREADS);
        loghash("store passwd as hash", stiger);
        memcpy(&crypto.passwd, stiger, config->hashlen);
        memcpy(&crypto.iv, config->iv, 8);
        bin_write_dbdata(dbp, &nextinode, sizeof(unsigned long long),
                         &crypto, sizeof(CRYPTO));
        free(stiger);
    }
#endif
    nextinode = 1;
    if (NULL == config->blockdatabs) {
        blockdatadir = s_dirname(config->blockdata);
        stat(blockdatadir, &stbuf);
        free(blockdatadir);
    } else {
        stat(config->blockdata, &stbuf);
    }
    write_nfi(nextinode);
    fs_mkdir("/", stbuf.st_mode);
    fs_mkdir("/.lessfs", stbuf.st_mode);
    dbmknod("/.lessfs/lessfs_stats", 0755 | S_IFREG, NULL, 0);
    tc_close(0);
    return;
}

int get_dir_inode(char *dname, struct stat *stbuf)
{
    char *p;
    int depth = 0;
    DDSTAT *filestat = NULL;
    int res = 0;
    unsigned long long inode = 1;

    FUNC;
    while (1) {
        p = strchr(dname, '/');
        if (NULL == p)
            break;
        p[0] = 0;
        LDEBUG("p=%s", p);
        if (depth == 0) {
            LDEBUG("Lookup inode 1");
            filestat =
                dnode_bname_to_inode(&inode, sizeof(unsigned long long),
                                     "/");
        } else {
            ddstatfree(filestat);
            inode = stbuf->st_ino;
            filestat =
                dnode_bname_to_inode(&inode, sizeof(unsigned long long),
                                     dname);
            if (NULL == filestat) {
                res = -ENOENT;
                break;
            }
        }
        memcpy(stbuf, &filestat->stbuf, sizeof(struct stat));
        LDEBUG("After memcpy %llu", stbuf->st_ino);
        p++;
        depth++;
        dname = p;
        if (NULL == p)
            break;
    }
    if (res == 0) {
        ddstatfree(filestat);
        LDEBUG("return stbuf.st_ino=%llu", stbuf->st_ino);
    }
    EFUNC;
    return (res);
}

/* Fill struct stat from cache if present in the cache
   return 1 when found or 0 when not found in cache. */
int get_realsize_fromcache(unsigned long long inode, struct stat *stbuf)
{
    int result = 0;
    const char *data;
    MEMDDSTAT *mddstat;
    int vsize;
    meta_lock((char *)__PRETTY_FUNCTION__);
    data = tctreeget(metatree, &inode, sizeof(unsigned long long), &vsize);
    if (data == NULL) {
        LDEBUG("inode %llu not found use size from database.", inode);
        release_meta_lock();
        return (result);
    }
    result++;
    mddstat = (MEMDDSTAT *) data;
    memcpy(stbuf, &mddstat->stbuf, sizeof(struct stat));
    LDEBUG("get_realsize_fromcache : return stbuf from cache : size %llu time %lu",
           stbuf->st_size,mddstat->stbuf.st_atim.tv_sec);
    release_meta_lock();
    return (result);
}

int dbstat(const char *filename, struct stat *stbuf)
{
    int retcode = 0;
    char *dname = NULL;
    char *bname = NULL;
    char *dupdname = NULL;
    char *mdupdname = NULL;
    DDSTAT *filestat = NULL;

    FUNC;
    dname = s_dirname((char *) filename);
    bname = s_basename((char *) filename);
    dupdname = s_strdup((char *) filename);
    mdupdname = dupdname;

// Walk the directory
    retcode = get_dir_inode(dupdname, stbuf);
    if (0 == retcode) {
        if (0 != strcmp(bname, dname)) {        /* This is the rootdir */
            // Now find the file within the directory
            filestat =
                dnode_bname_to_inode(&stbuf->st_ino,
                                     sizeof(unsigned long long), bname);
            if (NULL != filestat) {
                if (0 == strcmp(bname, filestat->filename)) {
                    if (0 ==
                        get_realsize_fromcache(filestat->stbuf.st_ino,
                                               stbuf)) {
                        memcpy(stbuf, &filestat->stbuf,
                               sizeof(struct stat));
                    }
                } else {
                    retcode = -ENOENT;
                }
                ddstatfree(filestat);
            } else {
                retcode = -ENOENT;
            }
        }
    } else
        retcode = -ENOENT;

    free(mdupdname);
    free(bname);
    free(dname);
    if (retcode == -ENOENT)
        LDEBUG("dbstat : File %s not found.", filename);
    EFUNC;
    return (retcode);
}

/* Free the ddstat stucture when not NULL */
void ddstatfree(DDSTAT * ddstat)
{
    if (NULL != ddstat) {
        LDEBUG("ddstatfree really free");
        free(ddstat);
        ddstat = NULL;
    }
}

MEMDDSTAT *value_tomem_ddstat(char *value, int size)
{
    MEMDDSTAT *memddstat;
    memddstat = s_malloc(size);
    memcpy(memddstat, value, size);
    return memddstat;
}

void memddstatfree(MEMDDSTAT * ddstat)
{
    if (NULL != ddstat) {
        LDEBUG("memddstatfree really free");
        free(ddstat);
    }
    ddstat = NULL;
    return;
}

void comprfree(compr * compdata)
{
    if (compdata) {
        if (compdata->data)
            free(compdata->data);
        free(compdata);
    }
}


DBT *lfsdecompress(DBT *cdata)
{
   DBT *data=NULL;
   int rsize;
   DBT *decrypted;

   decrypted=cdata;
#ifdef ENABLE_CRYPTO

   if (config->encryptdata){
      decrypted=decrypt(cdata);
   }
#endif
 
   if ( decrypted->data[0] == 0 || decrypted->data[0] == 'Q') {
      data = (DBT *)clz_decompress(decrypted->data, decrypted->size);
      return data;
   }
   if ( decrypted->data[0] == 'L') {
#ifdef LZO
      data = (DBT *)lzo_decompress(decrypted->data, decrypted->size);
      return data;
#else
      LFATAL("lessfs is compiled without LZO support");
      tc_close(0);
      exit(EXIT_DATAERR);
#endif
   }
   if ( decrypted->data[0] == 'G') {
      data=s_malloc(sizeof(DBT));
      data->data = (unsigned char *)tcgzipdecode((const char *)&decrypted->data[1], decrypted->size-1, &rsize);
      data->size=rsize;
      return data;
   }
   if ( decrypted->data[0] == 'B') {
      data=s_malloc(sizeof(DBT));
      data->data = (unsigned char *)tcbzipdecode((const char *)&decrypted->data[1], decrypted->size-1, &rsize);
      data->size=rsize;
      return data;
   }
   if ( decrypted->data[0] == 'D') {
      data=s_malloc(sizeof(DBT));
      data->data = (unsigned char *)tcinflate((const char *)&decrypted->data[1], decrypted->size-1, &rsize);
      data->size=rsize;
      return data;
   }
   die_dataerr("Data found with unsupported compression type %c",decrypted->data[0]);
   return data;
}

unsigned long long readBlock(unsigned long long blocknr,
                             const char *filename, char *blockdata,
                             unsigned long long inode, size_t size)
{
     char *cachedata;
     DBT *cdata;
     DBT *data;
     INOBNO inobno;
     int ret=0;
     CCACHEDTA *ccachedta;
     DBT *tdata;
     int vsize;
     unsigned long long p;

     inobno.inode=inode;
     inobno.blocknr=blocknr;

     write_lock((char *)__PRETTY_FUNCTION__);
     cachedata=(char *)tctreeget(delayedqtree, (void *)&inobno, sizeof(INOBNO), &vsize);
     if ( NULL == cachedata ) {
          cachedata=(char *)tctreeget(readcachetree, (void *)&inobno, sizeof(INOBNO), &vsize);
          if ( NULL == cachedata ) {
           tdata=check_block_exists(&inobno);
           if (NULL == tdata) { 
               release_write_lock();
               return (0);
           }
           cdata = search_dbdata(dbdta, tdata->data, tdata->size);
           if (NULL == cdata) {
               log_fatal_hash("Could not find block",tdata->data);
               die_dataerr("Could not find block");
           }
           DBTfree(tdata);
           data = lfsdecompress(cdata);
           memcpy(blockdata, data->data, data->size);
           ret=data->size;
           DBTfree(data);
           DBTfree(cdata);
// When we read a block < BLKSIZE there it is likely that we need
// to read it again so it makes sense to put it in a cache.
           if ( size < BLKSIZE ) {
// Make sure that we don't overflow the cache.
              if ( tctreernum(workqtree)*2 > config->cachesize ||\
                   tctreernum(delayedqtree)*2 > config->cachesize||\
                   tctreernum(readcachetree)*2 > config->cachesize ) {
                 flush_wait(inobno.inode);
                 flush_queue(0,0);
                 purge_read_cache(0,0);
              }
              ccachedta=s_zmalloc(sizeof(CCACHEDTA));
              p=(unsigned long long)ccachedta;
              ccachedta->dirty=0;
              ccachedta->pending=0;
              set_curtime(ccachedta->creationtime);
              memcpy(&ccachedta->data, blockdata, ret);
              ccachedta->datasize=ret;
              tctreeput(delayedqtree, (void *)&inobno, sizeof(INOBNO), (void *)&p, sizeof(unsigned long long));
           } 
           release_write_lock();
           ret=BLKSIZE;
           return(ret);
// Fetch the block from disk and put it in the cache.
        }
     }
     memcpy(&p,cachedata,vsize);
     ccachedta=(CCACHEDTA *)p;
     set_curtime(ccachedta->creationtime);
     memcpy(blockdata, &ccachedta->data, ccachedta->datasize);
     ret = BLKSIZE;
     release_write_lock();
     return (ret);
}

void delete_inuse(unsigned char *stiger)
{
     int ecode;
     loghash("delete_inuse", stiger);
     if ( !tchdbout(dbu, stiger, config->hashlen)) {
        ecode = tchdbecode(dbu);
        LFATAL("delete_inuse: failed to delete %s",tchdberrmsg(ecode));
        die_dataerr("delete_inuse : failed");
     }
     return;
}

void delete_dbb(INOBNO *inobno)
{
     int ecode;
     if ( !tchdbout(dbb, inobno, sizeof(INOBNO))){
        ecode = tchdbecode(dbb);
        LFATAL("delete_dbb: failed to delete %llu-%llu reason : %s",\
                inobno->inode,inobno->blocknr,tchdberrmsg(ecode));
     }
     return;
}

/* Return the number of times this block is linked to files */
unsigned long long getInUse(unsigned char *tigerstr)
{
    unsigned long long counter;
    DBT *data;

    loghash("getInuse search",tigerstr);
    if (NULL == tigerstr) {
        LDEBUG("getInuse : return 0");
        return (0);
    }

    data = search_dbdata(dbu, tigerstr, config->hashlen);
    if (NULL == data) {
        loghash("getInuse nothing found return 0 ",tigerstr);
        LDEBUG("getInuse nothing found return 0.");
        return (0);
    }
    memcpy(&counter, data->data, sizeof(counter));
    DBTfree(data);
    LDEBUG("getInuse : return %llu",counter);
    return counter;
}

void DBTfree(DBT * data)
{
    if (data) {
        if (data->data)
            if (data->data)
                free(data->data);
        free(data);
    }
    data = NULL;
}

void update_inuse(unsigned char *hashdata, 
                 unsigned long long inuse)
{
    loghash("update_inuse ", hashdata);
    if (inuse > 0) {
        bin_write_dbdata(dbu, hashdata, config->hashlen, (unsigned char *) &inuse,
                         sizeof(unsigned long long));
    } else {
        LDEBUG("update_inuse : skip %llu",inuse);
        loghash("update_inuse : skip", hashdata);
    }
    return;
}

void btbin_curwrite_dbdata(TCBDB * db, BDBCUR * cur, char *data,
                           int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbcurput(cur, data, datalen, BDBCPAFTER)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput2 failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

void btbin_write_dup(TCBDB * db, void *keydata, int keylen,
                     void *dataData, int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbputdup(db, keydata, keylen, dataData, datalen)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbputdup failed : %s", tcbdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

void btbin_write_dbdata(TCBDB * db, void *keydata, int keylen,
                        void *dataData, int datalen)
{
    int ecode;
    FUNC;
    if (!tcbdbput(db, keydata, keylen, dataData, datalen)) {
        ecode = tcbdbecode(db);
        die_dberr("tcbdbput failed : %s", tchdberrmsg(ecode));
    }
    if ( 0 == config->relax ) tcbdbsync(db);
    EFUNC;
}

void mbin_write_dbdata(TCMDB * db, void *keydata, int keylen,
                       void *dataData, int datalen)
{
    FUNC;
    tcmdbput(db, keydata, keylen, dataData, datalen);
    EFUNC;
}

void nbin_write_dbdata(TCNDB * db, void *keydata, int keylen,
                       void *dataData, int datalen)
{
    FUNC;
    tcndbput(db, keydata, keylen, dataData, datalen);
    EFUNC;
}

void bin_write_dbdata(TCHDB * db, void *keydata, int keylen,
                      void *dataData, int datalen)
{
    int ecode;
    if (!tchdbputasync(db, keydata, keylen, dataData, datalen)) {
        ecode = tchdbecode(db);
        die_dberr("tchdbputasync failed : %s", tchdberrmsg(ecode));
    }
}

/* Search in directory with inode dinode or key dinode for name bname 
   Return the inode of file bname                       */
DDSTAT *dnode_bname_to_inode(void *dinode, int dlen, char *bname)
{
    BDBCUR *cur;
    char *dbkey;
    int dbsize;
    char *dbvalue;
    DBT *statdata;
    DDSTAT *filestat = NULL;
    char *filename;
    DINOINO dinoino;
    unsigned long long keynode;
    unsigned long long valnode;

    FUNC;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, (char *) dinode, dlen)
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return NULL;
    }

    /* traverse records */
    while ((dbkey = tcbdbcurkey(cur, &dbsize)) != NULL) {
        if (0 != memcmp(dbkey, dinode, dlen)) {
            free(dbkey);
            break;
        }
        dbvalue = tcbdbcurval(cur, &dbsize);
        if (dbvalue) {
            memcpy(&valnode, dbvalue, sizeof(valnode));
            memcpy(&keynode, dbkey, sizeof(keynode));
            if (keynode == valnode && keynode != 1) {
                free(dbvalue);
                free(dbkey);
                tcbdbcurnext(cur);
                continue;
            }
            statdata =
                search_dbdata(dbp, &valnode, sizeof(unsigned long long));
            if (NULL == statdata) {
                LINFO("Unable to find file existing in dbp.\n");
                free(dbvalue);
                free(dbkey);
                return NULL;  
            } 
            filestat = value_to_ddstat(statdata);
            DBTfree(statdata);
            free(dbvalue);
            if (0 != filestat->filename[0]) {
                LDEBUG("compare bname %s with filestat->filename %s",
                       bname, filestat->filename);
                if (0 == strcmp(bname, filestat->filename)) {
                    free(dbkey);
                    break;
                }
            } else {
                memcpy(&dinoino.dirnode, dinode,
                       sizeof(unsigned long long));
                dinoino.inode = filestat->stbuf.st_ino;
                filename =
                    btsearch_keyval(dbl, &dinoino, sizeof(DINOINO), bname,
                                    strlen(bname));
                if (NULL != filename) {
                    memcpy(&filestat->filename, filename,
                           strlen(filename) + 1);
                    free(filename);
                    free(dbkey);
                    break;
                }
            }
            ddstatfree(filestat);
            filestat = NULL;
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    if (NULL != filestat) {
        LDEBUG("dnode_bname_to_inode : filestat->filename=%s inode %llu",
               filestat->filename, filestat->stbuf.st_ino);
    } else {
        LDEBUG("dnode_bname_to_inode : return NULL");
    }
    return filestat;
}

DBT *search_dbdata(TCHDB * db, void *key, int len)
{
    DBT *data;
    int size;

    data = s_malloc(sizeof(DBT));
    data->data = tchdbget(db, key, len, &size);
    data->size = (unsigned long) size;
    if (NULL == data->data) {
        LDEBUG("search_dbdata : return NULL");
        free(data);
        data = NULL;
    } else
        LDEBUG("search_dbdata : return %lu bytes", data->size);
    return data;
}

unsigned long long get_next_inode()
{
    DBT *data;
    unsigned long long nextinode = 0;
    FUNC;

    data = search_dbdata(dbp, (unsigned char *) "NFI", strlen("NFI"));
    if (NULL != data) {
        memcpy(&nextinode, data->data, sizeof(nextinode));
        DBTfree(data);
    }
    LDEBUG("Found next inode number: %llu", nextinode);
    EFUNC;
    return (nextinode);
}

DBT *search_memhash(TCMDB * db, void *key, int len)
{
    DBT *data;
    int size;

    FUNC;
    data = s_malloc(sizeof(DBT));
    data->data = tcmdbget(db, key, len, &size);
    data->size = (unsigned long) size;
    if (NULL == data->data) {
        LDEBUG("search_memhash : return NULL");
        free(data);
        data = NULL;
    } else
        LDEBUG("search_memhash : return %lu bytes", data->size);
    EFUNC;
    return data;
}

MEMDDSTAT *inode_meta_from_cache(unsigned long long inode)
{
    const char *dataptr;
    int vsize;

    MEMDDSTAT *memddstat = NULL;
    dataptr = tctreeget(metatree, &inode, sizeof(unsigned long long), &vsize);
    if (dataptr == NULL) {
        LDEBUG("inode %llu not found to update.", inode);
        release_meta_lock();
        return NULL;
    }
    memddstat = value_tomem_ddstat((char *) dataptr, vsize);
    return memddstat;
}

void update_filesize_onclose(unsigned long long inode)
{
    MEMDDSTAT *memddstat;

    memddstat = inode_meta_from_cache(inode);
    if (NULL == memddstat) {
        LDEBUG("inode %llu not found to update.", inode);
        return;
    }
    hash_update_filesize(memddstat, inode);
    memddstatfree(memddstat);
    return;
}

int update_filesize_cache(struct stat *stbuf, off_t size)
{
    const char *data;
    DBT *dskdata;
    int vsize;
    MEMDDSTAT *memddstat;
    DDSTAT *ddstat=NULL;
    DBT *ddbuf;
    time_t thetime;

    thetime = time(NULL);

    meta_lock((char *)__PRETTY_FUNCTION__);
    data = tctreeget(metatree, &stbuf->st_ino,
                          sizeof(unsigned long long), &vsize);
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data;
        memcpy(&memddstat->stbuf, stbuf, sizeof(struct stat));
        memddstat->stbuf.st_size = size;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mtim.tv_sec = thetime;
        memddstat->stbuf.st_mtim.tv_nsec=0;
        memddstat->updated = 1;
        ddbuf = create_mem_ddbuf(memddstat);
        tctreeput(metatree, &stbuf->st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
    } else {
        ddstatfree(ddstat);
        dskdata =
            search_dbdata(dbp, &stbuf->st_ino, sizeof(unsigned long long));
        if (NULL == dskdata) {
            release_meta_lock();
            return (-ENOENT);
        }
        ddstat = value_to_ddstat(dskdata);
        ddstat->stbuf.st_mtim.tv_sec = thetime;
        ddstat->stbuf.st_mtim.tv_nsec=0;
        ddstat->stbuf.st_ctim.tv_sec = thetime;
        ddstat->stbuf.st_ctim.tv_nsec=0;
        ddstat->stbuf.st_size = size;
        DBTfree(dskdata);
        dskdata = create_ddbuf(ddstat->stbuf, ddstat->filename, ddstat->real_size);
        bin_write_dbdata(dbp, &stbuf->st_ino, sizeof(unsigned long long),
                         (void *) dskdata->data, dskdata->size);
        DBTfree(dskdata);
    }
    ddstatfree(ddstat);
    release_meta_lock();
    return(0);
}


void update_filesize(unsigned long long inode, unsigned long long fsize,
                     unsigned int offsetblock, unsigned long long blocknr)
{
    const char *dataptr;
    DBT *tigerdata;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    int addblocks;
    INOBNO inobno;
    int vsize;

    meta_lock((char *)__PRETTY_FUNCTION__);
    dataptr = tctreeget(metatree, &inode, sizeof(unsigned long long), &vsize);
    if (dataptr == NULL)  goto endupdate;
    memddstat = (MEMDDSTAT *) dataptr;
    memddstat->updated++;
    memddstat->blocknr = blocknr;
    memddstat->stbuf.st_mtim.tv_sec=time(NULL);
    memddstat->stbuf.st_mtim.tv_nsec=0;

    addblocks = fsize / 512;
    if ((memddstat->stbuf.st_blocks + addblocks) * 512 <
        memddstat->stbuf.st_size + fsize)
        addblocks++;
    // The file has not grown in size. This is an updated block.
    if (((blocknr * BLKSIZE) + offsetblock + fsize) <=
        memddstat->stbuf.st_size) {
        inobno.inode = inode;
        inobno.blocknr = blocknr;
        //tigerdata = check_block_exists(&inobno);
        //if (NULL != tigerdata) {
            ddbuf = create_mem_ddbuf(memddstat);
            tctreeput(metatree, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
            DBTfree(ddbuf);
            //DBTfree(tigerdata);
            goto endupdate;
        //}
    }
    if (blocknr < 1) {
        if (memddstat->stbuf.st_size < fsize + offsetblock)
            memddstat->stbuf.st_size = fsize + offsetblock;
    } else {
        if (memddstat->stbuf.st_size <
            (blocknr * BLKSIZE) + fsize + offsetblock)
            memddstat->stbuf.st_size =
                fsize + offsetblock + (blocknr * BLKSIZE);
    }
    if (memddstat->stbuf.st_size > (512 * memddstat->stbuf.st_blocks)) {
        memddstat->stbuf.st_blocks = memddstat->stbuf.st_blocks + (BLKSIZE/512);
    }
    ddbuf = create_mem_ddbuf(memddstat);
    tctreeput(metatree, &inode, sizeof(unsigned long long),
                      (void *) ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
// Do not flush data until cachesize is reached
    if (memddstat->updated > config->cachesize) {
        hash_update_filesize(memddstat, inode);
        memddstat->updated = 0;
        ddbuf = create_mem_ddbuf(memddstat);
        tctreeput(metatree, &inode, sizeof(unsigned long long),
                          (void *) ddbuf->data, ddbuf->size);
        DBTfree(ddbuf);
    }
endupdate:
    release_meta_lock();
    return;
}


void create_hash_note(unsigned char *hash) 
{
   unsigned long long inuse=0;
   wait_hash_pending(hash);
   get_hash_lock((char *)__PRETTY_FUNCTION__);
   tctreeput(hashtree, (void *)hash, config->hashlen,&inuse,sizeof(unsigned long long));
   release_hash_lock();
}

void wait_hash_pending(unsigned char *hash)
{
   const char *data=NULL;  
   int vsize; 
   while(1) {
      get_hash_lock((char *)__PRETTY_FUNCTION__);
      data = tctreeget(hashtree, hash,
                       config->hashlen, &vsize);
      if ( NULL == data ) break;
      release_hash_lock();
      usleep(10);
   }
   release_hash_lock();
}

void delete_hash_note(unsigned char *hash)
{
   get_hash_lock((char *)__PRETTY_FUNCTION__);
   tctreeout(hashtree, (void *)hash, config->hashlen);
   release_hash_lock();
}

void hash_update_filesize(MEMDDSTAT * memddstat, unsigned long long inode)
{
    DBT *ddbuf;
// Wait until the data queue is written before we update the filesize
    if (memddstat->stbuf.st_nlink > 1) {
        ddbuf = create_ddbuf(memddstat->stbuf, NULL, memddstat->real_size);
    } else {
        ddbuf = create_ddbuf(memddstat->stbuf, memddstat->filename, memddstat->real_size);
    }
    bin_write_dbdata(dbp, &inode,
                     sizeof(unsigned long long), (void *) ddbuf->data,
                     ddbuf->size);
    DBTfree(ddbuf);
    return;
}

int btdelete_curkey(TCBDB * db, void *key, int keylen, void *kvalue,
                    int kvallen)
{
    BDBCUR *cur;
    char *value;
    int vsize;
    int ksize;
    char *dbkey;
    int ret = 1;

    FUNC;
    cur = tcbdbcurnew(db);
    if (!tcbdbcurjump(cur, key, keylen)) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    /* traverse records */
    while ((dbkey = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (0 != memcmp(dbkey, key, ksize)) {
            free(dbkey);
            break;
        }
        value = tcbdbcurval(cur, &vsize);
        if (value) {
            if (kvallen == vsize) {
                if (0 == memcmp(value, kvalue, kvallen)) {
                    ret = 0;
                    if (!tcbdbcurout(cur)) {
                        die_dataerr
                            ("Failed to delete key, this should never happen!");
                        ret = -ENOENT;
                    }
                    free(value);
                    free(dbkey);
                    break;
                }
            }
            free(value);
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    return (ret);
}

void *btsearch_keyval(TCBDB * db, void *key, int keylen, void *val,
                      int vallen)
{
    BDBCUR *cur;
    char *dbkey;
    char *dbvalue;
    void *ret = NULL;
    int size;

    FUNC;
    cur = tcbdbcurnew(db);
    if (!tcbdbcurjump(cur, key, keylen) && tcbdbecode(db) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return ret;
    }
    /* traverse records */
    while ((dbkey = tcbdbcurkey(cur, &size)) != NULL) {
        if (0 != memcmp(dbkey, key, keylen)) {
            free(dbkey);
            break;
        }
        dbvalue = tcbdbcurval(cur, &size);
        if (NULL != dbvalue) {
            if (NULL != val) {
                if (vallen == size) {
                    if (0 == memcmp(val, dbvalue, size)) {
                        ret = s_zmalloc(size + 1);
                        memcpy(ret, dbvalue, size);
                        free(dbvalue);
                        free(dbkey);
                        break;
                    }
                }
            } else {
                ret = s_zmalloc(size + 1);
                memcpy(ret, dbvalue, size);
                free(dbvalue);
                free(dbkey);
                break;
            }
            free(dbvalue);
        }
        free(dbkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    EFUNC;
    return ret;
}

/* return 0, 1 or 2 if more then 2 we stop counting */
int count_dirlinks(void *linkstr, int len)
{
    BDBCUR *cur;
    char *key;
    int size;
    int count = 0;

    cur = tcbdbcurnew(dbl);
    if (!tcbdbcurjump(cur, linkstr, len)
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    /* traverse records */
    while ((key = tcbdbcurkey(cur, &size)) != NULL) {
        if (len == size) {
            if (0 == memcmp(key, linkstr, len)) {
                count++;
            }
        }
        free(key);
        tcbdbcurnext(cur);
        if ( count > 1 ) break;
    }
    tcbdbcurdel(cur);
    return (count);
}

void delete_key(TCHDB * db, void *keydata, int len)
{
    int ecode;

    if (!tchdbout(db, keydata, len)) {
        ecode = tchdbecode(db);
        die_dataerr("Delete of key failed :%s", tchdberrmsg(ecode));
    }
}

void mdelete_key(TCMDB * db, void *keydata, int len)
{
    //FUNC;
    tcmdbout(db, keydata, len);
    //EFUNC;
}

void ndelete_key(TCNDB * db, void *keydata, int len)
{
    //FUNC;
    tcndbout(db, keydata, len);
    //EFUNC;
}


DBT *check_block_exists(INOBNO *inobno)
{
    DBT *data = NULL;
    FUNC;
    data = search_dbdata(dbb, inobno, sizeof(INOBNO));
    EFUNC;
    return data;
}

int db_unlink_file(const char *path)
{
    int res = 0;
    int haslinks = 0;
    int dir_links = 0;
    struct stat st;
    struct stat dirst;
    char *dname;
    char *bname;
//    unsigned char *stiger;
    unsigned long long inode;
//    unsigned long long inuse;
    time_t thetime;
    void *vdirnode;
//    DBT *bdata;
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
    inobno.blocknr = st.st_size/BLKSIZE;
    if ( inobno.blocknr * BLKSIZE  < st.st_size ) inobno.blocknr=1+st.st_size/BLKSIZE;
// Start deleting the actual data blocks.
    db_fs_truncate(&st, 0, bname);
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
        ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename, ddstat->real_size);
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

int fs_mkdir(const char *path, mode_t mode)
{
    unsigned long long inode;
    char *rdir;
    char *pdir;
    int rootdir = 0;
    int res;

    FUNC;
    LDEBUG("mode =%i", mode);
    if (0 == strcmp("/", path))
        rootdir = 1;
    inode = get_next_inode();
    write_file_ent(path, inode, S_IFDIR | mode, NULL, 0);
    if (rootdir) {
        rdir = as_sprintf("%s.", path);
    } else {
        rdir = as_sprintf("%s/.", path);
    }
    inode = get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    if (rootdir) {
        rdir = as_sprintf("%s..", path);
    } else {
        rdir = as_sprintf("%s/..", path);
    }
    inode = get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    pdir = s_dirname((char *) path);
    res = update_parent_time(pdir,1);
    free(pdir);
    return (res);
}

DBT *tc_compress(unsigned char *dbdata, unsigned long dsize)
{
  DBT *compressed;
  int rsize;
  char *data=NULL;

  compressed=s_malloc(sizeof(DBT));
  switch (config->compression)
  {
  case 'G':
    data=tcgzipencode((const char*)dbdata, dsize, &rsize);
    if (rsize > dsize ) goto def;
    compressed->data=s_malloc(rsize+1);
    compressed->data[0]='G';
    break;
  case 'B':
    data=tcbzipencode((const char*)dbdata, dsize, &rsize);
    if (rsize > dsize ) goto def;
    compressed->data=s_malloc(rsize+1);
    compressed->data[0]='B';
    break;
  case 'D':
    data=tcdeflate((const char*)dbdata, dsize, &rsize);
    if (rsize > dsize ) goto def;
    compressed->data=s_malloc(rsize+1);
    compressed->data[0]='D';
    break;
  default:
def:
    if (data) free(data);
    compressed->data=s_malloc(dsize+1);
    memcpy(&compressed->data[1],dbdata,dsize);
    compressed->data[0]=0;
    compressed->size=dsize+1;
    return compressed;
  }
  memcpy(&compressed->data[1],data,rsize);
  compressed->size=rsize+1;
  free(data);
  return compressed;
}

DBT *lfscompress(unsigned char *dbdata, unsigned long dsize) 
{
  DBT *compressed=NULL;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif

  switch (config->compression)
  {
  case 'L':
#ifdef LZO
    compressed = (DBT *)lzo_compress(dbdata, dsize);
#else 
    LFATAL("lessfs is compiled without LZO support");
    tc_close(0);
    exit(EXIT_DATAERR);
#endif
    break;
  case 'Q':
    compressed = (DBT *)clz_compress(dbdata, dsize);
    break;
  default:
    compressed=(DBT *)tc_compress(dbdata, dsize);
  }
  
#ifdef ENABLE_CRYPTO
  if (config->encryptdata) {
     encrypted = encrypt(compressed->data, compressed->size);
     DBTfree(compressed);
     return encrypted;
  }
#endif
  return compressed;
} 

unsigned int db_commit_block(unsigned char *dbdata,
                             INOBNO inobno,unsigned long dsize)
{
    unsigned char *stiger=NULL;
    DBT *compressed;
    unsigned long long inuse;
    unsigned int ret = 0;

    FUNC;
    stiger=thash(dbdata, dsize,MAX_ALLOWED_THREADS-1);
    create_hash_note(stiger);
    inuse = getInUse(stiger);
    if (0 == inuse) {
       compressed=lfscompress((unsigned char *) dbdata, dsize);
       ret = compressed->size;
       bin_write_dbdata(dbdta,stiger,config->hashlen,compressed->data,compressed->size);
       DBTfree(compressed);
    } else {
        loghash("commit_block : only updated inuse for hash ", stiger);
    }
    inuse++;
    update_inuse(stiger, inuse);
    LDEBUG("dbb %llu-%llu",inobno.inode,inobno.blocknr);
    bin_write_dbdata(dbb,(char *)&inobno,sizeof(INOBNO),stiger,config->hashlen);
    delete_hash_note(stiger);
    free(stiger);
    return (ret);
}

void partial_truncate_block(struct stat *stbuf, unsigned long long blocknr,
                            unsigned int offset)
{
    unsigned char *blockdata;
    DBT *uncompdata;
    INOBNO inobno;
    DBT *data;
#ifdef ENABLE_CRYPTO
    DBT *encrypted;
#endif
    unsigned char *stiger;
    unsigned long long inuse;
    int ecode;
    
    FUNC;
    LDEBUG("partial_truncate_block : inode %llu, blocknr %llu, offset %u",
           stbuf->st_ino, blocknr, offset);
    inobno.inode = stbuf->st_ino;
    inobno.blocknr = blocknr;

    data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
    if (NULL == data) {
        LDEBUG("Deletion of non existent block?");
        return;
    }
    stiger = s_malloc(data->size);
    memcpy(stiger, data->data, data->size);
    DBTfree(data);

#ifdef ENABLE_CRYPTO
    if (config->encryptdata){
      encrypted=search_dbdata(dbdta, stiger, config->hashlen);
      data = decrypt(encrypted);
      DBTfree(encrypted);
    } else data = search_dbdata(dbdta, stiger, config->hashlen);
#else
    data = search_dbdata(dbdta, stiger, config->hashlen);
#endif
    if ( NULL == data ) {
        log_fatal_hash("Hmmm, did not expect this to happen.",stiger);
        die_dataerr("Hmmm, did not expect this to happen.");
    }
    create_hash_note(stiger);
    inuse = getInUse(stiger);
    if (inuse == 1) {
        loghash("partial_truncate_block : delete hash", stiger);
        delete_inuse(stiger);
        delete_dbb(&inobno);
        if (!tchdbout(dbdta, stiger, config->hashlen)) {
           ecode = tchdbecode(dbdta);
           log_fatal_hash("Failed to delete hash",stiger);
           LFATAL("Could not delete %llu-%llu : %s",inobno.inode,inobno.blocknr, tchdberrmsg(ecode));
           die_dataerr("partial_truncate_block : Could not delete expected data");
        }
    } else {
        if (inuse > 1)
            inuse--;
        delete_dbb(&inobno);
        update_inuse(stiger, inuse);
    }
    delete_hash_note(stiger);
    blockdata = s_zmalloc(BLKSIZE);
    uncompdata = lfsdecompress(data);
    if ( uncompdata->size >= offset ) {
       memcpy(blockdata, uncompdata->data, offset);
    } else {
       memcpy(blockdata, uncompdata->data, uncompdata->size);
    }
    DBTfree(uncompdata);
    db_commit_block(blockdata,inobno,offset);
    free(stiger);
    DBTfree(data);
    free(blockdata);
    return;
}

int db_fs_truncate(struct stat *stbuf, off_t size, char *bname)
{
    unsigned int offsetblock;
    unsigned long long blocknr;
    unsigned long long lastblocknr;
    unsigned long long inuse;
    unsigned char *stiger;
    off_t oldsize;
    DBT *data;
    INOBNO inobno;
    time_t thetime;
    int fromcache=0;

    FUNC;
    LDEBUG("lessfs_truncate inode %llu - size %llu", stbuf->st_ino,
           (unsigned long long) size);
    thetime = time(NULL);
    blocknr = size / BLKSIZE;
    offsetblock = size - (blocknr * BLKSIZE);
    oldsize = stbuf->st_size;
    lastblocknr = oldsize / BLKSIZE;
    // Truncate filesize.
    update_filesize_cache(stbuf, size);
    LDEBUG("lessfs_truncate : truncate new block %llu, oldblock %llu",
           blocknr, lastblocknr);
    inobno.inode = stbuf->st_ino;
    while (lastblocknr >= blocknr) {
        fromcache=0;
        if ( offsetblock != 0 && lastblocknr == blocknr ) break;
        inobno.blocknr = lastblocknr;
        data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
        if (NULL == data) {
            LDEBUG
                ("Deletion of non existent block inode : %llu, blocknr %llu",
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
        LDEBUG("lessfs_truncate Search to delete blocknr %llu:",
               lastblocknr);
        loghash("lessfs_truncate tiger :", stiger);
        DBTfree(data);
        create_hash_note(stiger);
        inuse = getInUse(stiger);
        if (inuse == 1) {
            loghash("truncate : delete hash", stiger);
            delete_inuse(stiger);
            delete_dbb(&inobno);
            if (!tchdbout(dbdta, stiger, config->hashlen)) {
                 log_fatal_hash("Failed to delete hash",stiger);
                 LFATAL("Could not delete %llu-%llu",inobno.inode,inobno.blocknr);
                 die_dataerr("Could not delete expected data");
            }
        } else {
            if (inuse > 1)
                inuse--;
            delete_dbb(&inobno);
            update_inuse(stiger, inuse);
        }
        delete_hash_note(stiger);
        if (lastblocknr > 0)
            lastblocknr--;
        free(stiger);
    }
    LDEBUG("offsetblock = %u", offsetblock);
    if (0 != offsetblock)
        partial_truncate_block(stbuf, lastblocknr, offsetblock);
    return (0);
}

int update_parent_time(char *path, int linkcount)
{
    int res;
    struct stat stbuf;
    time_t thetime;

    FUNC;
    LDEBUG("update_parent_time : %s", path);
    thetime = time(NULL);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    res = dbstat(path, &stbuf);
    if (0 != res)
        return (res);
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
    stbuf.st_mtim.tv_sec = thetime;
    stbuf.st_mtim.tv_nsec=0;
    stbuf.st_nlink=stbuf.st_nlink+linkcount;
    res = update_stat(path, &stbuf);
    EFUNC;
    return (res);
}

int fs_rmdir(const char *path)
{
    int res;
    char *dotstr;
    char *dotdotstr;
    char *dname;
    unsigned long long dirnode;
    unsigned long long keynode;
    unsigned long long pathnode;
    unsigned long long dirnodes;

    FUNC;
    LDEBUG("rmdir called : %s", path);

    pathnode = get_inode(path);
    dirnodes = has_nodes(pathnode);
    if (0 != dirnodes) {
        LDEBUG("fs_rmdir : Cannot remove directory %s with %llu files",
               path, dirnodes);
        EFUNC;
        return -ENOTEMPTY;
    }

    dname = s_dirname((char *) path);
    dotstr = as_sprintf("%s/.", path);
    dotdotstr = as_sprintf("%s/..", path);

    keynode = get_inode(dotstr);
    LDEBUG("inode for %s is %llu", dotstr, keynode);
    delete_key(dbp, &keynode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &keynode, sizeof(unsigned long long));

    keynode = get_inode(dotdotstr);
    delete_key(dbp, &keynode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &keynode, sizeof(unsigned long long));

    dirnode = get_inode(dname);
    delete_key(dbp, &pathnode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &dirnode, sizeof(unsigned long long),
                    &pathnode, sizeof(unsigned long long));
    btdelete_curkey(dbdirent, &pathnode, sizeof(unsigned long long),
                    &pathnode, sizeof(unsigned long long));
    free(dotstr);
    free(dotdotstr);
    res = update_parent_time(dname,-1);
    free(dname);
    return (res);
}

unsigned long long get_inode(const char *path)
{
    struct stat stbuf;

    FUNC;
    if (0 != dbstat(path, &stbuf)) {
        LDEBUG("get_inode : nothing found for %s", path);
        return (0);
    }
    EFUNC;
    return (stbuf.st_ino);
}

/* Return 0 when the directory is empty, 1 when it contains files */
unsigned long long has_nodes(unsigned long long inode)
{
    unsigned long long res = 0;
    BDBCUR *cur;
    unsigned long long filenode;
    char *filenodestr;
    DBT *filedata;
    bool dotdir = 0;
    char *key;
    DDSTAT *ddstat;
    int size;
    unsigned long long keyval;

    FUNC;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, &inode, sizeof(unsigned long long))
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    while ((key = tcbdbcurkey(cur, &size)) != NULL) {
        memcpy(&keyval, key, sizeof(unsigned long long));
        if (keyval != inode) {
            free(key);
            break;
        }
        filenodestr = (char *) tcbdbcurval(cur, &size);
        memcpy(&filenode, filenodestr, sizeof(unsigned long long));
        filedata =
            search_dbdata(dbp, &filenode, sizeof(unsigned long long));
        if (NULL != filedata) {
            ddstat = value_to_ddstat(filedata);
            DBTfree(filedata);
            LDEBUG("Compare : %llu %llu", filenode, inode);
            if (filenode == inode)
                dotdir = 1;
            if (NULL != ddstat->filename) {
                if (0 == strcmp(ddstat->filename, "."))
                    dotdir = 1;
                if (0 == strcmp(ddstat->filename, ".."))
                    dotdir = 1;
            }
            if (!dotdir) {
                LDEBUG
                    ("has_nodes : Found file in directory %s filenode %llu inode %llu",
                     ddstat->filename, filenode, inode);
                res++;
            }
            ddstatfree(ddstat);
        }
        free(key);
        free(filenodestr);
        dotdir = 0;
        if ( 0 != res ) break;
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    LDEBUG("inode %llu contains files", inode);
    EFUNC;
    return (res);
}

void fs_read_hardlink(struct stat stbuf, DDSTAT * ddstat, void *buf,
                      fuse_fill_dir_t filler, struct fuse_file_info *fi)
{
    BDBCUR *cur;
    char *linkkey;
    int ksize;
    DINOINO dinoino;
    char *filename;

    FUNC;
    cur = tcbdbcurnew(dbl);
    dinoino.dirnode = stbuf.st_ino;
    dinoino.inode = ddstat->stbuf.st_ino;
    if (!tcbdbcurjump(cur, &dinoino, sizeof(DINOINO))
        && tcbdbecode(dbl) != TCESUCCESS)
        die_dataerr("Unable to find linkname, run fsck.");
    while ((linkkey = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (0 != memcmp(linkkey, &dinoino, sizeof(DINOINO))) {
            LDEBUG("fs_read_hardlink : linkkey != dinoino");
            free(linkkey);
            break;
        }
        filename = (char *) tcbdbcurval(cur, &ksize);
        memcpy(&ddstat->filename, filename, strlen(filename) + 1);
        free(filename);
        LDEBUG("fs_read_hardlink : fil_fuse_info %s size %i",
               ddstat->filename, ksize);
        fil_fuse_info(ddstat, buf, filler, fi);
        ddstat->filename[0] = 0;
        free(linkkey);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    EFUNC;
    return;
}

void fil_fuse_info(DDSTAT * ddstat, void *buf, fuse_fill_dir_t filler,
                   struct fuse_file_info *fi)
{
    struct stat st;
    char *bname;

    memcpy(&st, &ddstat->stbuf, sizeof(struct stat));
    bname = s_basename(ddstat->filename);
    if (NULL != bname) {
        // Don't show the directory
        if (0 != strcmp(bname, "/")) {
            LDEBUG("Fill filler with %s", bname);
            filler(buf, bname, &st, 0);
        }
    }
    free(bname);
}

int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info *fi)
{
    int retcode = 0;
    BDBCUR *cur;
    int size, res;
    int ksize;
    char *key;
    struct stat stbuf;
    unsigned long long keynode;
    unsigned long long filenode;
    char *filenodestr;
    DBT *filedata;
    DDSTAT *ddstat;
    FUNC;

    (void) offset;
    (void) fi;
    LDEBUG("Called fs_readdir with path %s", (char *) path);

    res = dbstat(path, &stbuf);
    if (0 != res)
        return -ENOENT;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, &stbuf.st_ino, sizeof(unsigned long long))
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (-ENOENT);
    }
    while ((key = tcbdbcurkey(cur, &ksize)) != NULL) {
        memcpy(&keynode, key, sizeof(unsigned long long));
        if (stbuf.st_ino != keynode) {
            free(key);
            break;
        }
        filenodestr = tcbdbcurval(cur, &size);
        memcpy(&filenode, filenodestr, sizeof(unsigned long long));
        if (filenode == keynode) {
            free(filenodestr);
            free(key);
            tcbdbcurnext(cur);
            continue;
        }
        LDEBUG("GOT filenode %llu", filenode);
        filedata =
            search_dbdata(dbp, &filenode, sizeof(unsigned long long));
        if (NULL != filedata) {
            ddstat = value_to_ddstat(filedata);
            DBTfree(filedata);
            if (ddstat->filename[0] == 0) {
                fs_read_hardlink(stbuf, ddstat, buf, filler, fi);
            } else {
                fil_fuse_info(ddstat, buf, filler, fi);
            }
            ddstatfree(ddstat);
        }
        free(key);
        free(filenodestr);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    LDEBUG("fs_readdir: return");
    return (retcode);
}

int fs_link(char *from, char *to)
{
    int res = 0;
    unsigned long long inode;
    unsigned long long todirnode;
    unsigned long long fromdirnode;
    struct stat stbuf;
    struct stat tobuf;
    struct stat frombuf;
    char *bfrom;
    char *bto;
    char *todir;
    char *fromdir;
    DBT *ddbuf;
    DBT *symdata;
    time_t thetime;
    DINOINO dinoino;
    const char *data;
    int vsize;
    MEMDDSTAT *memddstat;

    FUNC;
    LDEBUG("fs_link called with from=%s to=%s", from, to);
    res = dbstat(from, &stbuf);

    if (res != 0)
        return (res);
    fromdir = s_dirname(from);
    res = dbstat(fromdir, &frombuf);
    todir = s_dirname(to);
    res = dbstat(todir, &tobuf);
    if (res != 0) {
        free(todir);
        free(fromdir);
        return -ENOENT;
    }
    bfrom = s_basename(from);
    bto = s_basename(to);

/* Update inode nrlinks */
    todirnode = tobuf.st_ino;
    fromdirnode = frombuf.st_ino;
    inode = stbuf.st_ino;
    // Update nr of links.
    stbuf.st_nlink++;
    thetime = time(NULL);

    data = tctreeget(metatree, &stbuf.st_ino,
                          sizeof(unsigned long long), &vsize);
    if (NULL != data) {
        memddstat = (MEMDDSTAT *) data;
        memddstat->stbuf.st_ctim.tv_sec = thetime;
        memddstat->stbuf.st_ctim.tv_nsec=0;
        memddstat->stbuf.st_mtim.tv_sec = thetime;
        memddstat->stbuf.st_mtim.tv_nsec=0;
        memddstat->stbuf.st_nlink++;
        memddstat->updated = 1;
        //memset(&memddstat->filename,0,2);
        ddbuf = create_mem_ddbuf(memddstat);
        tctreeput(metatree, &stbuf.st_ino,
                          sizeof(unsigned long long), (void *) ddbuf->data,
                          ddbuf->size);
        DBTfree(ddbuf);
    } 
    stbuf.st_ctim.tv_sec = thetime;
    stbuf.st_ctim.tv_nsec=0;
    ddbuf = create_ddbuf(stbuf, NULL, 0);
    LDEBUG("fs_link : update links on %llu to %i", inode, stbuf.st_nlink);
    bin_write_dbdata(dbp, &inode, sizeof(unsigned long long),
                     ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
/* Link dest filename inode to dest directory if it does not exist*/
    if (0 ==
        bt_entry_exists(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long))) {
        LDEBUG("fs_link : write link %llu : %llu", todirnode, inode);
        btbin_write_dup(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
    }

/* Link some more, hardlink a symlink. */
    if (S_ISLNK(stbuf.st_mode)) {
        LDEBUG("fs_link : hardlink a symlink");
        symdata = search_dbdata(dbs, &inode, sizeof(unsigned long long));
        if (NULL == symdata)
            die_dataerr("Unable to read symlink");
        DBTfree(symdata);
    }
/* Write L_destinodedir_inode : dest filename */
    dinoino.dirnode = tobuf.st_ino;
    dinoino.inode = stbuf.st_ino;
    LDEBUG("A. fs_link : write link %llu-%llu : %s", tobuf.st_ino,
           stbuf.st_ino, bto);
    btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bto, strlen(bto));
    btbin_write_dup(dbl, &stbuf.st_ino, sizeof(unsigned long long),
                    &dinoino, sizeof(DINOINO));

/* Write Lfrominode_inode : from filename */
    dinoino.dirnode = frombuf.st_ino;
    dinoino.inode = stbuf.st_ino;
    if (stbuf.st_nlink == 2) {
        btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bfrom,
                        strlen(bfrom));
        btbin_write_dup(dbl, &stbuf.st_ino, sizeof(unsigned long long),
                        &dinoino, sizeof(DINOINO));
    }
    res = update_parent_time(todir,0);
    free(todir);
    free(fromdir);
    free(bfrom);
    free(bto);
    EFUNC;
    return (res);
}

int bt_entry_exists(TCBDB * db, void *parent, int parentlen, void *value,
                    int vallen)
{
    int res = 0;
    BDBCUR *cur;
    char *dbvalue;
    char *key;
    int ksize;

    FUNC;
    cur = tcbdbcurnew(dbdirent);
    if (!tcbdbcurjump(cur, parent, parentlen)
        && tcbdbecode(db) != TCESUCCESS) {
        tcbdbcurdel(cur);
        return (res);
    }
    while ((key = tcbdbcurkey(cur, &ksize)) != NULL) {
        if (ksize != parentlen) {
            free(key);
            break;
        }
        if (0 != memcmp(key, parent, parentlen)) {
            free(key);
            break;
        }
        dbvalue = tcbdbcurval2(cur);
        if (dbvalue) {
            if (0 == memcmp(value, dbvalue, vallen))
                res = 1;
            free(dbvalue);
        }
        free(key);
        tcbdbcurnext(cur);
        if ( res == 1 ) break;
    }
    tcbdbcurdel(cur);
    LDEBUG("bt_entry_exists : returns %i", res);
    EFUNC;
    return (res);
}

int fs_symlink(char *from, char *to)
{
    int res = 0;
    char *todir;

    todir = s_dirname(to);
    dbmknod(to, 0777 | S_IFLNK, from, 0);
    res = update_parent_time(todir,0);
    free(todir);
    return (res);
}

int fs_readlink(const char *path, char *buf, size_t size)
{
    int res = 0;
    DBT *data;
    unsigned long long inode;

    FUNC;
    inode = get_inode(path);
    if (0 == inode)
        return (-ENOENT);

    data = search_dbdata(dbs, &inode, sizeof(unsigned long long));
    if (NULL == data) {
        res = -ENOENT;
    } else {
        if (size - 1 > data->size) {
            memcpy(buf, data->data, data->size + 1);
        } else {
            memcpy(buf, data->data, size - 1);
        }
        DBTfree(data);
    }
    return (res);
}

int fs_rename_link(const char *from, const char *to, struct stat stbuf)
{
    unsigned long long fromnode;
    unsigned long long tonode;
    unsigned long long inode;
    char *fromdir;
    char *todir;
    char *bfrom;
    char *bto;
    struct stat st;
    int res = 0;
    DINOINO dinoino;

    FUNC;

    LDEBUG("fs_rename_link from: %s : to %s", (char *) from, (char *) to);
    if (0 == strcmp(from, to))
        return (0);
    if (-ENOENT != dbstat(to, &st)) {
        if (NULL != config->blockdatabs) {
            db_unlink_file(to);
        } else {
            file_unlink_file(to);
        }
    }
    fromdir = s_dirname((char *) from);
    todir = s_dirname((char *) to);
    bfrom = s_basename((char *) from);
    bto = s_basename((char *) to);
    inode = stbuf.st_ino;

    fromnode = get_inode(fromdir);
    tonode = get_inode(todir);
    if (0 == fromnode)
        die_dataerr("Unable to find directory %s for file %s", fromdir,
                    from);
    if (0 == tonode)
        die_dataerr("Unable to find directory %s for file %s", todir, to);

    dinoino.dirnode = fromnode;
    dinoino.inode = stbuf.st_ino;
    btdelete_curkey(dbl, &dinoino, sizeof(DINOINO), bfrom, strlen(bfrom));
    if (count_dirlinks(&dinoino, sizeof(DINOINO)) > 1) {
        btdelete_curkey(dbdirent, &fromnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
        btbin_write_dup(dbdirent, &tonode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
    }
    dinoino.dirnode = tonode;
    dinoino.inode = stbuf.st_ino;
    btbin_write_dup(dbl, &dinoino, sizeof(DINOINO), bto, strlen(bto));
    free(fromdir);
    free(bfrom);
    free(bto);
    free(todir);
    EFUNC;
    return (res);
}

void update_cache(unsigned long long inode, struct stat *stbuf)
{
    char *dataptr;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    int vsize;

    FUNC;
    LDEBUG("update_cache nlinks : %u", stbuf->st_nlink);
    dataptr=(char *)tctreeget(metatree, (void *)&inode, sizeof(unsigned long long), &vsize);
    if (dataptr == NULL) {
        return;
    }
    memddstat = (MEMDDSTAT *) dataptr;
    memcpy(&memddstat->stbuf, &stbuf, sizeof(struct stat));
    ddbuf = create_mem_ddbuf(memddstat);
    memddstat->updated = 0;
    tctreeput(metatree, (void *)&inode, sizeof(unsigned long long), ddbuf->data, ddbuf->size);
    DBTfree(ddbuf);
    hash_update_filesize(memddstat, inode);
    EFUNC;
    return;
}

void sync_all_filesizes()
{
    unsigned long long inode;
    const char *key;

    tctreeiterinit(metatree);
    while ((key = tctreeiternext2(metatree)) != NULL) {
       memcpy(&inode, key, sizeof(unsigned long long));
       update_filesize_onclose(inode);
    }
}


int fs_rename(const char *from, const char *to, struct stat stbuf)
{
    DBT *dataptr;
    DDSTAT *ddstat;
    DBT *ddbuf;
    int res = 0;
    unsigned long long inode;
    time_t thetime;
    char *bto;
    char *bfrom;
    char *fromdir;
    char *todir;
    unsigned long long fromdirnode;
    unsigned long long todirnode;
    unsigned long long tonode;
    struct stat st;
    unsigned long long dirnodes;

    FUNC;
    
    LDEBUG("fs_rename from: %s : to %s", (char *) from, (char *) to);
    todir = s_dirname((char *) to);
    todirnode = get_inode(todir);
    tonode = get_inode(to);
    bto = s_basename((char *) to);
    bfrom = s_basename((char *) from);
    if (-ENOENT != dbstat(to, &st)) {
        if (S_ISDIR(st.st_mode)) {
            LDEBUG("fs_rename bto %s bfrom %s", bto, bfrom);
            dirnodes = has_nodes(tonode);
            if (0 != dirnodes) {
                if (0 != strcmp(bto, bfrom)) {
                    LDEBUG
                        ("fs_rename : Cannot rename directory %llu with %llu files",
                         todirnode, dirnodes);
                    free(todir);
                    free(bfrom);
                    free(bto);
                    EFUNC;
                    return -ENOTEMPTY;
                }
            }
            fs_rmdir(to);
        } else {
            LDEBUG("fs_rename : destination file %s exists, unlink_file.",
                   to);
            if (NULL != config->blockdatabs) {
                db_unlink_file(to);
            } else {
                file_unlink_file(to);
            }
        }
    }
    free(bfrom);
    inode = stbuf.st_ino;
    fromdir = s_dirname((char *) from);
    fromdirnode = get_inode(fromdir);
    LDEBUG("fs_rename : bto = %s", bto);
    dataptr = search_dbdata(dbp, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        die_dataerr("Failed to find file %llu", inode);
    }
    ddstat = value_to_ddstat(dataptr);
    thetime = time(NULL);
    ddstat->stbuf.st_ctim.tv_sec = thetime;
    ddstat->stbuf.st_ctim.tv_nsec=0;
    ddbuf = create_ddbuf(ddstat->stbuf, (char *) bto, ddstat->real_size);
    bin_write_dbdata(dbp, &inode,
                     sizeof(unsigned long long), (void *) ddbuf->data,
                     ddbuf->size);
    if (fromdirnode != todirnode) {
        LDEBUG("fs_rename : rename inode %llu : %llu to another path %llu",
               inode, fromdirnode, todirnode);
        btdelete_curkey(dbdirent, &fromdirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
        btbin_write_dup(dbdirent, &todirnode, sizeof(unsigned long long),
                        &inode, sizeof(unsigned long long));
    }
    DBTfree(dataptr);
    DBTfree(ddbuf);
    ddstatfree(ddstat);
    free(bto);
    free(fromdir);
    free(todir);
    EFUNC;
    return (res);
}

int update_stat(char *path, struct stat *stbuf)
{
    DDSTAT *ddstat;
    MEMDDSTAT *memddstat;
    DBT *ddbuf;
    DBT *dataptr;
    const char *cdata;
    int vsize;
    unsigned long long inode;

    FUNC;
    inode = stbuf->st_ino;


    cdata = tctreeget(metatree, (unsigned char *)&inode,
                           sizeof(unsigned long long), &vsize);
    if ( NULL != cdata ) {
       memddstat = (MEMDDSTAT *) cdata;
       memcpy(&memddstat->stbuf, stbuf, sizeof(struct stat));
       ddbuf = create_mem_ddbuf(memddstat);
       tctreeput(metatree, &inode, sizeof(unsigned long long),
                              (void *) ddbuf->data, ddbuf->size);
       DBTfree(ddbuf);
       return(0);
    }
    dataptr = search_dbdata(dbp, &inode, sizeof(unsigned long long));
    if (dataptr == NULL) {
        return (-ENOENT);
    }
    ddstat = value_to_ddstat(dataptr);
    memcpy(&ddstat->stbuf, stbuf, sizeof(struct stat));
    ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename, ddstat->real_size);
    bin_write_dbdata(dbp, &inode,
                     sizeof(unsigned long long), (void *) ddbuf->data,
                     ddbuf->size);
    DBTfree(dataptr);
    DBTfree(ddbuf);
    ddstatfree(ddstat);
    EFUNC;
    return (0);
}

void parseconfig(int mklessfs)
{
    char *cache, *flushtime;
    unsigned int cs = 0;
    unsigned long calc;
#ifdef ENABLE_CRYPTO
    unsigned long long pwl = 0;
    unsigned char *stiger;
    DBT *ivdb;
    CRYPTO *crypto;
#endif
    char *iv;
    char *dbpath;
    struct stat stbuf;

    FUNC;
    config = s_malloc(sizeof(struct configdata));
    // BLOCKDATA_IO_TYPE tokyocabinet (default), file_io
    config->blockdata = read_val("BLOCKDATA_PATH");
    iv = getenv("BLOCKDATA_IO_TYPE");
    if (NULL == iv) {
        config->blockdata_io_type = "tokyocabinet";
        config->blockdatabs = read_val("BLOCKDATA_BS");
        LINFO("The selected data store is tokyocabinet.");
    } else {
        if (0 == strncasecmp(iv, "file_io", strlen("file_io"))) {
            config->blockdata_io_type = "file_io";
            config->blockdatabs = NULL;
            config->freelist = read_val("FREELIST_PATH");
            config->freelistbs = read_val("FREELIST_BS");
            LINFO("The selected data store is file_io.");
        } else
            config->blockdatabs = read_val("BLOCKDATA_BS");
    }
    iv=getenv("ENABLE_TRANSACTIONS");
    if (NULL == iv) {
        config->transactions = 0;
        LINFO("Lessfs transaction support is disabled.");
    } else {
        if (0 == strncasecmp(iv, "on", strlen("on"))) {
            config->transactions = 1;
            LINFO("Lessfs transaction support is enabled.");
        } else {
            config->transactions = 0;
            LINFO("Lessfs transaction support is disabled.");
        }
    }
    config->blockusage = read_val("BLOCKUSAGE_PATH");
    config->blockusagebs = read_val("BLOCKUSAGE_BS");
    config->dirent = read_val("DIRENT_PATH");
    config->direntbs = read_val("DIRENT_BS");
    config->fileblock = read_val("FILEBLOCK_PATH");
    config->fileblockbs = read_val("FILEBLOCK_BS");
    config->meta = read_val("META_PATH");
    config->metabs = read_val("META_BS");
    config->hardlink = read_val("HARDLINK_PATH");
    config->hardlinkbs = read_val("HARDLINK_BS");
    config->symlink = read_val("SYMLINK_PATH");
    config->symlinkbs = read_val("SYMLINK_BS");
    config->encryptdata = 0;
    config->encryptmeta = 1;
    config->hashlen = 24;
    config->hash="MHASH_TIGER192";
    config->selected_hash = MHASH_TIGER192;
    iv = getenv("COMPRESSION");
    config->compression='Q';
    if ( NULL != iv ) {
      if ( 0 == strcasecmp("qlz",iv)) config->compression='Q';
#ifdef LZO
      if ( 0 == strcasecmp("lzo",iv)) config->compression='L';
#else
      if ( 0 == strcasecmp("lzo",iv)) die_dataerr("LZO support is not available: please configure with --with-lzo");
#endif
      if ( 0 == strcasecmp("gzip",iv)) config->compression='G';
      if ( 0 == strcasecmp("bzip",iv)) config->compression='B';
      if ( 0 == strcasecmp("deflate",iv)) config->compression='D';
      if ( 0 == strcasecmp("disabled",iv)) config->compression=0;
      if ( 0 == strcasecmp("none",iv)) config->compression=0;
    }
    iv = getenv("HASHNAME");
    if ( NULL != iv ) {
       config->hash=iv;
       if ( 0 == strcmp("MHASH_SHA256", iv )) {
          config->selected_hash=MHASH_SHA256;
          LINFO("Hash SHA256 has been selected");
       }
       if ( 0 == strcmp("MHASH_SHA512", iv )) {
          config->selected_hash=MHASH_SHA512;
          LINFO("Hash SHA512 has been selected");
       }
       if ( 0 == strcmp("MHASH_WHIRLPOOL",iv)) {
          config->selected_hash=MHASH_WHIRLPOOL;
          LINFO("Hash WHIRLPOOL has been selected");
       }
       if ( 0 == strcmp("MHASH_HAVAL256",iv)) {
          config->selected_hash=MHASH_HAVAL256;
          LINFO("Hash HAVAL has been selected");
       }
       if ( 0 == strcmp("MHASH_SNEFRU256",iv)) {
          config->selected_hash=MHASH_SNEFRU256;
          LINFO("Hash SNEFRU has been selected");
       }
       if ( 0 == strcmp("MHASH_RIPEMD256",iv)) {
          config->selected_hash=MHASH_RIPEMD256;
          LINFO("Hash RIPEMD256 has been selected");
       }
       if ( config->selected_hash == MHASH_TIGER192 )
          LINFO("Hash MHASH_TIGER192 has been selected");
    } else  LINFO("Hash MHASH_TIGER192 been selected");
    iv = getenv("HASHLEN");
    if (NULL != iv ) {
       if ( atoi(iv) >= 20 && atoi(iv) <= MAX_HASH_LEN ) {
           if ( atoi(iv) > 24 && config->selected_hash == MHASH_TIGER192 ) {
              die_dataerr("MHASH_TIGER192 can not be used with MAX_HASH_LEN > 24");
           }
           config->hashlen=atoi(iv);
       } else {
           LFATAL("The hash length is invalid.");
           exit(EXIT_USAGE);
       }
    }
    LINFO("Lessfs uses a %i bytes long hash.", config->hashlen);
    iv = getenv("SYNC_RELAX");
    if (NULL == iv) {
        config->relax = 0;
    } else {
        config->relax = atoi(iv);
        if (0 != config->relax) {
            LINFO
                ("Lessfs fsync does not sync the databases to the disk when fsync is called on an inode");
        }
    }
    iv = getenv("INSPECT_DISK_INTERVAL");
    if (NULL == iv) {
        config->inspectdiskinterval = 1;
    } else {
        config->inspectdiskinterval = atoi(iv);
    }
    iv = getenv("DYNAMIC_DEFRAGMENTATION");
    config->defrag = 0;
    if (NULL != iv) {
        if (0 == strcasecmp("on", iv)) {
            config->defrag = 1;
        }
    }
    if (config->defrag)
        LINFO("Automatic defragmentation is enabled.");
    cache = read_val("CACHESIZE");
    if (NULL != cache)
        cs = atoi(cache);
    if (cs <= 0)
        cs = 1;
    calc=cs;
    config->cachesize = (calc * 1024 * 1024) / MAX_FUSE_BLKSIZE;
    flushtime = read_val("COMMIT_INTERVAL");
    cs = atoi(flushtime);
    if (cs <= 0)
        cs = 30;
    config->flushtime = cs;
    LINFO("cache %llu data blocks", config->cachesize);

    if (mklessfs == 1) {
        dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
        if (-1 != stat(dbpath, &stbuf)) {
            fprintf(stderr,
                    "Data %s already exists, please remove it and try again\n",
                    dbpath);
            exit(EXIT_DATAERR);
        }
    }
    if (mklessfs == 2 ) {
        drop_databases();
        if (NULL == dbp)
           tc_open(0,1);
    } else {
        if (NULL == dbp)
           tc_open(0,0);
    }
    if (mklessfs == 0) {
#ifdef ENABLE_CRYPTO
        iv = read_val("ENCRYPT_DATA");
        if (NULL != iv) {
            if (0 == strcasecmp(iv, "ON")) {
                config->encryptdata = 1;
                iv = getenv("ENCRYPT_META");
                LINFO("Data encryption is on");
                if (NULL != iv) {
                    if (0 != strcasecmp(iv, "ON")) {
                        LINFO("Metadata encryption is off");
                        config->encryptmeta = 0;
                    }
                }
            }
        }
        if (config->encryptdata) {
            /*if (config->encryptdata) {
                if (NULL == config->blockdatabs) {
                    fprintf(stderr,"Encryption is not supported with file_io\n");
                    die_dataerr
                        ("Encryption is not supported with file_io");
                }
            }*/
            if ( NULL == getenv("PASSWORD")){
               config->passwd =
                   (unsigned char *) s_strdup(getpass("Password: "));
            } else config->passwd = s_strdup(getenv("PASSWORD"));
            unsetenv("PASSWORD"); /* Eat it after receiving..*/
            stiger=thash(config->passwd, strlen((char *) config->passwd),MAX_ALLOWED_THREADS);
            ivdb = search_dbdata(dbp, &pwl, sizeof(unsigned long long));
            if (NULL == ivdb) {
                tc_close(0);
                die_dataerr
                    ("The filesystem has not been formatted with encryption support.");
            }
            config->iv = s_malloc(8);
            crypto = (CRYPTO *) ivdb->data;
            memcpy(config->iv, crypto->iv, 8);
            //config->passwd is plain, crypto->passwd is hashed.
            checkpasswd(crypto->passwd);
            free(stiger);
            DBTfree(ivdb);
        }
#endif
        if (0 == get_next_inode())
            die_dataerr
                ("Please format lessfs with mklessfs before mounting!");
    }
    return;
}

#ifdef ENABLE_CRYPTO
void checkpasswd(char *cryptopasswd)
{
    unsigned char *stiger;

    FUNC;
    stiger=thash(config->passwd, strlen((char *) config->passwd), MAX_ALLOWED_THREADS);
    if (0 != memcmp(cryptopasswd, stiger, config->hashlen)) {
        sleep(5);
        fprintf(stderr, "Invalid password entered.\n");
        exit(EXIT_PASSWD);
    }
    free(stiger);
    EFUNC;
    return;
}
#endif

void clear_dirty()
{
    unsigned char *stiger;
    char *brand;
    brand=as_sprintf("LESSFS_DIRTY");
    stiger=thash((unsigned char *)brand, strlen(brand), MAX_ALLOWED_THREADS);
    tchdbout(dbu,stiger,config->hashlen);
    free(stiger);
    free(brand);
    return;
}

int get_blocksize()
{
    unsigned char *stiger;
    char *brand;
    INUSE *finuse;
    int blksize=4096;
    unsigned long long inuse;

    brand=as_sprintf("LESSFS_BLOCKSIZE");
    stiger=thash((unsigned char *)brand, strlen(brand), MAX_ALLOWED_THREADS);
    if ( config->blockdatabs != NULL ) {
      inuse=getInUse(stiger);
      if ( 0 == inuse ) {
         brand_blocksize();
         blksize=BLKSIZE;
      } else {
         blksize=inuse;
      }
    } else {
      finuse=file_get_inuse(stiger);
      if ( NULL == finuse ) {
         brand_blocksize();
         blksize=BLKSIZE;
      } else {
         blksize=finuse->inuse;
      }
    }
    free(stiger);
    free(brand);
    return(blksize);
}

/* Add the hash for string LESSFS_BLOCKSIZE
   to lessfs so that we know the blocksize for
   lessfsck and when someone is foolish enough to
   remount with a different blocksize */
void brand_blocksize()
{
    unsigned char *stiger;
    char *brand;
    INUSE inuse;

    brand=as_sprintf("LESSFS_BLOCKSIZE");
    stiger=thash((unsigned char *)brand, strlen(brand), MAX_ALLOWED_THREADS);
    if ( config->blockdatabs != NULL ) {
        update_inuse(stiger,BLKSIZE);
    } else {
        inuse.inuse=BLKSIZE;
        inuse.size=0;
        inuse.offset=0;
        file_update_inuse(stiger,&inuse);
    }
    free(stiger);
    free(brand);
    return;
}

void drop_databases()
{
   char *dbpath;
   struct stat stbuf;

   dbpath = as_sprintf("%s/fileblock.tch", config->fileblock);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/blockusage.tch", config->blockusage);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/metadata.tcb", config->meta);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/symlink.tch", config->symlink);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/dirent.tcb", config->dirent);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   dbpath = as_sprintf("%s/hardlink.tcb", config->hardlink);
   if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
   free(dbpath);
   if (NULL != config->blockdatabs) {
      dbpath = as_sprintf("%s/blockdata.tch", config->blockdata);
      if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
      free(dbpath);
   } else {
      dbpath = as_sprintf("%s/freelist.tcb", config->freelist);
      if (-1 != stat(dbpath, &stbuf) ) unlink(dbpath);
      free(dbpath);
      unlink(config->blockdata);
   }
}

void lessfs_trans_stamp()
{
    unsigned long long ldate;
    time_t tdate;
    INUSE finuse;
    struct tm * timeinfo;

    tdate=time(NULL);
    timeinfo = localtime ( &tdate );
    ldate=tdate;
    LDEBUG("lessfs_trans_stamp : filesystem commit at %s",asctime(timeinfo));
    if ( NULL == config->blockdatabs) {
       finuse.inuse=ldate;
       finuse.size=0;
       finuse.offset=0;
       bin_write_dbdata(dbu, config->commithash, config->hashlen, (unsigned char *)&finuse,
                        sizeof(INUSE));
    } else {
       bin_write_dbdata(dbu, config->commithash, config->hashlen, (unsigned char *)&ldate,
                        sizeof(unsigned long long));
    }
    return;
}

DBT *search_nhash(TCNDB * db, void *key, int len)
{
    DBT *data;
    int size;

    FUNC;
    data = s_malloc(sizeof(DBT));
    data->data = tcndbget(db, key, len, &size);
    data->size = (unsigned long) size;
    if (NULL == data->data) {
        LDEBUG("search_nhash : return NULL");
        free(data);
        data = NULL;
    } else
        LDEBUG("search_nhash : return %lu bytes", data->size);
    EFUNC;
    return data;
}

void flush_abort(unsigned long long inode)
{
    char *key;
    int size;
    int vsize;
    char *val;
    unsigned long long p;
    INOBNO *inobno;
    CCACHEDTA *ccachedta;
    int pending;

    LDEBUG("flush_abort");
reflush:
    pending=0; 
    tctreeiterinit(delayedqtree);
    while ( NULL != (key=(char *)tctreeiternext(delayedqtree, &size))){
       val=(char *)tctreeget(delayedqtree, (void *)key, size, &vsize);
       if ( NULL != val ) {
          memcpy(&p,val,vsize);
          ccachedta=(CCACHEDTA *)p;
          inobno=(INOBNO *)key;
          if ( inode == inobno->inode ) {
             if (ccachedta->pending == 1 ) {
                LDEBUG("Wait to flush pending inode %llu-%llu",inobno->inode,inobno->blocknr);
                goto reflush;
             }
             LDEBUG("flush_abort inode %llu-%llu",inobno->inode,inobno->blocknr);
             tctreeout(readcachetree,key,size);
             tctreeout(workqtree,key,size);
             tctreeout(delayedqtree,key,size);
             //LFATAL("flush_abort free %llu",p);
             free(ccachedta);
          }
       }
    }
    LDEBUG("/flush_abort");
    return;
}

int wait_pending() 
{
  int pending=0;
  char *key;
  int size;
  int vsize;
  char *val;
  unsigned long long p;
  INOBNO *inobno;
  CCACHEDTA *ccachedta;

  FUNC;
  tctreeiterinit(delayedqtree);
  while ( NULL != (key=(char *)tctreeiternext(delayedqtree, &size))){
     val=(char *)tctreeget(delayedqtree, (void *)key, size, &vsize);
     if ( NULL != val ) {
        memcpy(&p,val,vsize);
        ccachedta=(CCACHEDTA *)p;
        inobno=(INOBNO *)key;
        if ( ccachedta->pending == 1 ) pending=1;
     }
  }
  EFUNC;
  return pending;
}

void flush_wait(unsigned long long inode)
{
   char *key;
    int size;
    int vsize;
    char *val;
    unsigned long long p;
    INOBNO *inobno;
    CCACHEDTA *ccachedta;

    tctreeiterinit(delayedqtree);
    while ( NULL != (key=(char *)tctreeiternext(delayedqtree, &size))){
       val=(char *)tctreeget(delayedqtree, (void *)key, size, &vsize);
       if ( NULL != val ) {
          memcpy(&p,val,vsize);
          ccachedta=(CCACHEDTA *)p;
          inobno=(INOBNO *)key;
          if ( inode == inobno->inode ) {
             if ( ccachedta->dirty == 1 ) {
                while(ccachedta->pending == 1 ) {
                   usleep(10);
                }
             }
             cook_cache(key, size, ccachedta, MAX_ALLOWED_THREADS-1);
//HIER????
             
             tctreeput(readcachetree,key,size,val,vsize);
             tctreeout(workqtree,key,size);
             tctreeout(delayedqtree,key,size);
//             free(ccachedta);
          }
       }
    }
    return;
}

// Both write_lock and global_lock need to be set.
void flush_queue(unsigned long long inode, bool force) {
    char *key;
    int size;
    int vsize;
    char *val;
    unsigned long long p;
    INOBNO *inobno;
    CCACHEDTA *ccachedta;

    tctreeiterinit(delayedqtree);
    while ( NULL != (key=(char *)tctreeiternext(delayedqtree, &size))){
       val=(char *)tctreeget(delayedqtree, (void *)key, size, &vsize);
       if ( NULL != val ) {
          memcpy(&p,val,vsize);
          ccachedta=(CCACHEDTA *)p;
          inobno=(INOBNO *)key;
          if ( ccachedta->dirty == 1 ) {
             if ( ccachedta->pending != 1 ) {
// Only queue to be processed when it's not in the queue.
                if ( NULL == tctreeget(workqtree, (void *)key, size, &vsize)) {
                   if ( inode == 0 ) {
// The processing threads will now pickup the block
                      tctreeput(workqtree, (void *)inobno, sizeof(INOBNO), (void *)&p, sizeof(unsigned long long));
                   } else {
                      if ( inode == inobno->inode ) {
                         LDEBUG("Flush specified inode %llu ->  %llu-%llu from the cache",inode,inobno->inode,inobno->blocknr);
                         tctreeput(workqtree, (void *)inobno, sizeof(INOBNO), (void *)&p, sizeof(unsigned long long));
                      }
                   }
                }
             }
          }
       }
    }
    LDEBUG("Database delayedqtree now holds %llu records and has size %llu",tctreernum(delayedqtree),tctreemsiz(delayedqtree));
    LDEBUG("Database workqtree now holds %llu records and has size %llu",tctreernum(cachetree),tctreemsiz(cachetree));
    return;
}

void purge_read_cache(unsigned long long inode, bool force)
{
    char *key;
    int size;
    int vsize;
    char *val;
    unsigned long long p;
    INOBNO *inobno;
    CCACHEDTA *ccachedta;
    struct timeval thetime; 

    unsigned int age=CACHE_MAX_AGE;
    unsigned int uage=0;
    
    set_curtime(thetime);

    while(1) {
       tctreeiterinit(readcachetree);
       while ( NULL != (key=(char *)tctreeiternext(readcachetree, &size))){
          val=(char *)tctreeget(readcachetree, (void *)key, size, &vsize);
          if ( NULL != val ) {
             memcpy(&p,val,vsize);
             ccachedta=(CCACHEDTA *)p;
             inobno=(INOBNO *)key;
             if ( inode == 0 ) {
                 if ( force ) {
                    tctreeout(readcachetree,key,size);
                    free(ccachedta);
                 } else {
                    if ( ccachedta->creationtime.tv_sec < thetime.tv_sec + age) {
                        if ( ccachedta->creationtime.tv_usec < thetime.tv_usec + uage) {
                           tctreeout(readcachetree,key,size);
                           free(ccachedta);
                           if (tctreernum(readcachetree)*2 < config->cachesize-(config->cachesize/4)) break;
                        }
                    }
                 }
                 continue;
             }
             if ( inode == inobno->inode ) {
                if ( force ) {
                    tctreeout(readcachetree,key,size);
                    free(ccachedta);
                } else {
                   if ( ccachedta->creationtime.tv_sec < thetime.tv_sec + age) {
                        if ( ccachedta->creationtime.tv_usec < thetime.tv_usec + uage) {
                           tctreeout(readcachetree,key,size);
                           free(ccachedta);
                           if (tctreernum(readcachetree)*2 < config->cachesize-(config->cachesize/4)) break;
                        }
                    }
                }
             }
          }
       }
       if (force) break;
       if (tctreernum(readcachetree)*2 < config->cachesize-(config->cachesize/4)) break;
       if ( uage == 999000) {
          uage=0;
          if ( age > 0 ) {
              age--;
          } else break;
       } else {
          uage=uage+1000;
       }
    }
    return;
}

void update_meta(unsigned long long inode, unsigned long size, int sign)
{
   const char *data;
   int vsize;
   MEMDDSTAT *mddstat;

   LDEBUG("update_meta : inode %llu database.", inode);
   meta_lock((char *)__PRETTY_FUNCTION__);
   data = tctreeget(metatree, &inode, sizeof(unsigned long long), &vsize);
   if (data == NULL) {
       LFATAL("inode %llu not found use size from database.", inode);
       release_meta_lock();
       return;
   }
   mddstat = (MEMDDSTAT *) data;
   if ( sign == 1 ) {
      mddstat->real_size=mddstat->real_size+size;
   } else {
      mddstat->real_size=mddstat->real_size-size;
   }
   tctreeput(metatree, &inode, sizeof(unsigned long long), (void *)mddstat,vsize);
   release_meta_lock();
   return;
}

void tc_write_cache(CCACHEDTA *ccachedta, INOBNO *inobno) 
{
   unsigned long long inuse;
   DBT *compressed;

   create_hash_note((unsigned char *)&ccachedta->hash);
   inuse = getInUse((unsigned char *)&ccachedta->hash);
   if (inuse == 0) {
      compressed=lfscompress(ccachedta->data, ccachedta->datasize);
      bin_write_dbdata(dbdta,&ccachedta->hash,config->hashlen,compressed->data,compressed->size);
      if ( ccachedta->newblock == 1 ) update_meta(inobno->inode,compressed->size,1);
      if ( ccachedta->updated != 0 ) {
         if ( compressed->size > ccachedta->updated ) { 
            update_meta(inobno->inode,compressed->size-ccachedta->updated,1);
         } else {
            update_meta(inobno->inode,ccachedta->updated-compressed->size,0);
         }
      }
      DBTfree(compressed);
   }
   bin_write_dbdata(dbb,(char *)inobno,sizeof(INOBNO),ccachedta->hash,config->hashlen);
   inuse++;
   update_inuse((unsigned char *)&ccachedta->hash, inuse);
   delete_hash_note((unsigned char *)&ccachedta->hash);
   ccachedta->dirty=0;
   ccachedta->pending=0;
   ccachedta->newblock=0;
   return;
}

void cook_cache(char *key, int ksize, CCACHEDTA *ccachedta, int tnum)
{
   INOBNO *inobno;
   unsigned char *hash;

   inobno=(INOBNO *)key;
   LDEBUG("cook_cache : %llu-%llu",inobno->inode,inobno->blocknr);
   hash=thash((unsigned char *)&ccachedta->data, ccachedta->datasize, tnum);
   memcpy(&ccachedta->hash,hash,config->hashlen);
   free(hash);
   if ( config->blockdatabs != NULL ){
     tc_write_cache(ccachedta, inobno); 
   } else {
     fl_write_cache(ccachedta, inobno);
   }
   return;
}

void start_flush_commit()
{
   unsigned long long lastoffset=0;
   while ( 0 != tctreernum(workqtree)) {
      LDEBUG("Waiting for %llu records to drain",tctreernum(workqtree));
      write_lock((char *)__PRETTY_FUNCTION__);
      flush_queue(0,0);
      release_write_lock();
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
}

void end_flush_commit() {
   if ( config->blockdatabs == NULL ) {
      tcbdbsync(freelist);
   }else tchdbsync(dbdta);
   tchdbsync(dbu);
   tchdbsync(dbb);
   //free(config->lfsstats);
   //config->lfsstats=lessfs_stats();
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
}


char *lessfs_stats()
{
    char *lfsmsg;
    char *line;
    char *key;
    int ksize;
    DDSTAT *ddstat;
    DBT *data;
    unsigned long long inode;
    char *nfi = "NFI";
    CRYPTO *crypto;
    const char **lines = NULL;
    int count = 1;
    lines = s_malloc((tchdbrnum(dbp) + 1) * sizeof(char *));

    lines[0] = as_sprintf("  INODE             SIZE  COMPRESSED_SIZE  FILENAME\n");
    /* traverse records */
    tchdbiterinit(dbp);
    while ((key = tchdbiternext(dbp, &ksize)) != NULL) {
        if (0 != memcmp(key, nfi, 3)) {
            memcpy(&inode, key, sizeof(unsigned long long));
            data = search_dbdata(dbp, &inode, sizeof(unsigned long long));
            if (inode == 0) {
                crypto = (CRYPTO *) data->data;
            } else {
                ddstat = value_to_ddstat(data);
                if (S_ISREG(ddstat->stbuf.st_mode)) {
#ifdef x86_64
                   line=as_sprintf
                       ("%7lu  %15lu  %15llu  %s\n",
                        ddstat->stbuf.st_ino, ddstat->stbuf.st_size,
                        ddstat->real_size, ddstat->filename);
#else
                   line=as_sprintf
                       ("%7llu  %15llu  %15llu  %s\n",
                        ddstat->stbuf.st_ino, ddstat->stbuf.st_size,
                        ddstat->real_size, ddstat->filename);
#endif
                   lines[count++] = line;
                }
                ddstatfree(ddstat);
            }
            DBTfree(data);
        }
        free(key);
    }
    lfsmsg = as_strarrcat(lines, count);
    while (count) {
        free((char *)lines[--count]);
    }
    free(lines);
    return lfsmsg;
}

void set_curtime(struct timeval tv)
{
   struct timezone tz;
   tz.tz_minuteswest=0;
   tz.tz_dsttime=0;
   gettimeofday(&tv, &tz);
   return;
}
