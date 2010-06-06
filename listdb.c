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
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fuse.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tcutil.h>
#include <tchdb.h>
#include <tcbdb.h>
#include <stdbool.h>
#include "lib_safe.h"
#include "lib_cfg.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#endif
#include "lib_qlz.h"
#include "lib_tc.h"
#ifdef SHA3
#include "lib_BMW_SHA3api_ref.h"
#endif
#include "file_io.h"
#include "commons.h"

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif

u_int32_t db_flags, env_flags;

#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }
#define die_syserr() { LFATAL("Fatal system error : %s",strerror(errno)); exit(EXIT_SYSTEM); }

void usage(char *fname)
{
    fprintf(stderr, "%s /data_path /meta_patch\n", fname);
}

char *ascii_hash(unsigned char *bhash)
{
    char *ascii_hash = NULL;
    int n;
    char *p1 = NULL, *p2 = NULL;

    for (n = 0; n < config->hashlen; n++) {
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
    return (ascii_hash);
}


void listdbu()
{
    char *asc_hash;
    char *key, *value;
    int size;
    unsigned long long counter;

    /* traverse records */
    tchdbiterinit(dbu);
    while ((key = tchdbiternext2(dbu)) != NULL) {
        value = tchdbget(dbu, key, config->hashlen, &size);
        asc_hash = ascii_hash((unsigned char *) key);
        memcpy(&counter, value, sizeof(counter));
        printf("%s : %llu\n", asc_hash, counter);
        free(asc_hash);
        free(value);
        free(key);
    }
}

void flistdbu()
{
    char *asc_hash;
    char *key;
    int size;
    INUSE *inuse;
    unsigned long rsize;
    unsigned long long nextoffet;

    /* traverse records */
    tchdbiterinit(dbu);
    while ((key = tchdbiternext2(dbu)) != NULL) {
        if ( 0 == memcmp(config->nexthash,key,config->hashlen)) {
           inuse = tchdbget(dbu, key, config->hashlen, &size);
           memcpy(&nextoffet,inuse,sizeof(unsigned long long));
           printf("\nnextoffset = %llu\n\n", nextoffset);  
        } else {
           inuse = tchdbget(dbu, key, config->hashlen, &size);
           asc_hash = ascii_hash((unsigned char *) key);
           printf("%s	: %llu\n", asc_hash, inuse->inuse);
           printf("offset						: %llu\n",inuse->offset);
           printf("size						: %lu\n", inuse->size);
           rsize=round_512(inuse->size);
           printf("round size					: %lu\n\n", rsize);
           free(asc_hash);
           free(inuse);
        }
        free(key);
    }
}

void listdta()
{
    char *asc_hash;
    char *key;

    /* traverse records */
    tchdbiterinit(dbdta);
    while ((key = tchdbiternext2(dbdta)) != NULL) {
        //value = tchdbget(dbu, key, TIGERLEN, &size);
        asc_hash = ascii_hash((unsigned char *) key);
        printf("%s\n", asc_hash);
        free(asc_hash);
        //free(value);
        free(key);
    }
}


void listdbb()
{
    char *asc_hash = NULL;
    char *key, *value;
    int size;
    int vsize;
    unsigned long long inode;
    unsigned long long blocknr;

    /* traverse records */
    tchdbiterinit(dbb);
    while ((key = tchdbiternext(dbb, &size)) != NULL) {
        value = tchdbget(dbb, key, size, &vsize);
        asc_hash = ascii_hash((unsigned char *) value);
        memcpy(&inode, key, sizeof(unsigned long long));
        memcpy(&blocknr, key + sizeof(unsigned long long),
               sizeof(unsigned long long));
        printf("%llu-%llu : %s\n", inode, blocknr, asc_hash);
        free(asc_hash);
        free(value);
        free(key);
    }
}

/* List the symlink database */
void list_symlinks()
{
    char *key, *value;
    int size;
    int sp;

    unsigned long long inode;
    /* traverse records */
    tchdbiterinit(dbs);
    while ((key = tchdbiternext(dbs, &size)) != NULL) {
        value = tchdbget(dbs, key, size, &sp);
        memcpy(&inode, key, sizeof(unsigned long long));
        printf("%llu : %s\n", inode, value);
        free(value);
        free(key);
    }
}

void list_hardlinks()
{
    char *key, *value;
    int size;
    int ksize;
    unsigned long long inode;
    DINOINO dinoino;
    BDBCUR *cur;

    /* traverse records */
    cur = tcbdbcurnew(dbl);
    tcbdbcurfirst(cur);
    while ((key = tcbdbcurkey(cur, &ksize)) != NULL) {
        value = tcbdbcurval(cur, &size);
        if (ksize == sizeof(DINOINO)) {
            memcpy(&dinoino, key, sizeof(DINOINO));
            printf("dinoino %llu-%llu : inode %s\n", dinoino.dirnode,
                   dinoino.inode, value);
        } else {
            memcpy(&inode, key, sizeof(unsigned long long));
            memcpy(&dinoino, value, sizeof(DINOINO));
            printf("inode %llu : %llu-%llu dinoino\n", inode,
                   dinoino.dirnode, dinoino.inode);
        }
        free(value);
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
}

void listdbp()
{
    char *key, *value;
    int size;
    int ksize;
    DDSTAT *ddstat;
    DBT *data;
    unsigned long long inode;
    char *nfi = "NFI";
    CRYPTO *crypto;


    /* traverse records */
    tchdbiterinit(dbp);
    while ((key = tchdbiternext(dbp, &ksize)) != NULL) {
        if (0 == memcmp(key, nfi, 3)) {
            value = tchdbget(dbp, key, strlen(key), &size);
            memcpy(&inode, value, sizeof(unsigned long long));
            printf("%s : %llu\n", key, inode);
            free(value);
        } else {
            memcpy(&inode, key, sizeof(unsigned long long));
            data = search_dbdata(dbp, &inode, sizeof(unsigned long long));
            if (inode == 0) {
                crypto = (CRYPTO *) data->data;
            } else {
                ddstat = value_to_ddstat(data);
#ifdef x86_64
                printf
                    ("ddstat->filename %s \n      ->inode %lu  -> size %lu  -> real_size %llu time %lu\n",
                     ddstat->filename, ddstat->stbuf.st_ino,
                     ddstat->stbuf.st_size, ddstat->real_size, ddstat->stbuf.st_atim.tv_sec);
#else
                printf
                    ("ddstat->filename %s \n      ->inode %llu -> size %llu -> real_size %llu time %lu\n",
                     ddstat->filename, ddstat->stbuf.st_ino,
                     ddstat->stbuf.st_size, ddstat->real_size, ddstat->stbuf.st_atim.tv_sec);
#endif
                if (S_ISDIR(ddstat->stbuf.st_mode)) {
                    printf("      ->filename %s is a directory\n",
                           ddstat->filename);
                }
                ddstatfree(ddstat);
            }
            DBTfree(data);
        }
        free(key);
    }
}

void listfree()
{
    unsigned long long mbytes;
    unsigned long long offset;
    BDBCUR *cur;
    unsigned long long *dbkey;
    unsigned long long *dboffset;
    int dbsize;

    cur = tcbdbcurnew(freelist);
    tcbdbcurfirst(cur);
    while ((dbkey = tcbdbcurkey(cur, &dbsize)) != NULL) {
            if ((dboffset = tcbdbcurval(cur, &dbsize)) == NULL){
               fprintf(stderr,"No value for key");
               exit(EXIT_SYSTEM);
            }
            memcpy(&offset, dboffset, sizeof(unsigned long long));
            memcpy(&mbytes, dbkey, sizeof(unsigned long long));
            printf("offset = %llu : blocks = %llu : bytes = %llu\n", offset, mbytes, mbytes*512);
            free(dboffset);
            free(dbkey);
            tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    return;
}


void listdirent()
{
    BDBCUR *cur;
    char *key, *value;
    int size;
    unsigned long long dir;
    unsigned long long ent;

    /* traverse records */
    cur = tcbdbcurnew(dbdirent);
    tcbdbcurfirst(cur);
    while ((key = tcbdbcurkey2(cur)) != NULL) {
        memcpy(&dir, key, sizeof(dir));
        value = tcbdbcurval(cur, &size);;
        if (value) {
            memcpy(&ent, value, sizeof(ent));
            printf("%llu:%llu\n", dir, ent);
            free(value);
        }
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(argv[0]);
    if (-1 == r_env_cfg(argv[1]))
        usage(argv[0]);
    parseconfig(0);
    fuse_get_context()->uid = 0;
    fuse_get_context()->gid = 0;
    printf("\n\ndbp\n");
    listdbp();
    printf("\n\ndbu\n");
    if ( NULL != config->blockdatabs ) {
       listdbu();
       printf("\n\ndbdta\n");
       listdta();
    } else {
       flistdbu();
       listfree();
    }
    printf("\n\ndbb\n");
    listdbb();
    printf("\n\ndbdirent\n");
    listdirent();
    printf("\n\ndbs (symlinks)\n");
    list_symlinks();
    printf("\n\ndbl (hardlinks)\n");
    list_hardlinks();
    tc_close(1);
    exit(0);
}
