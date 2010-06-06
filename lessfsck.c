/*
 *   Lessfs: A data deduplicating filesystem.
 *   Copyright (C) 2008 Mark Ruijter <mruijter@lessfs.com>
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <fuse.h>

#include <tcutil.h>
#include <tchdb.h>
#include <tcbdb.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lib_log.h"
#include "lib_safe.h"
#include "lib_cfg.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#endif
#include "lib_qlz.h"
#include "lib_tc.h"
#include "file_io.h"

#ifdef ENABLE_CRYPTO
unsigned char *passwd = NULL;
#endif

#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }
#define die_syserr() { LFATAL("Fatal system error : %s",strerror(errno)); exit(EXIT_SYSTEM); }

#include "commons.h"
#define BACKSPACE 8

unsigned long long lafinode;
extern unsigned long long nextoffset;
unsigned long long detected_size=0;
extern int fdbdta;

struct option_info {
    char *configfile;
    int optimizetc;
    int fast;
};
struct option_info chkoptions;

unsigned long long check_inuse(unsigned char *lfshash)
{
    unsigned long long counter;
    DBT *data;

    if (NULL == lfshash)
        return (0);

    data = search_dbdata(dbu, lfshash, config->hashlen);
    if (NULL == data) {
        LDEBUG("check_inuse nothing found return 0.");
        return (0);
    }
    memcpy(&counter, data->data, sizeof(counter));
    DBTfree(data);
    return counter;
}

void show_progress()
{
   static int progress=0;

   progress++;
   if (progress == 100 ) printf("%c|",BACKSPACE);
   if (progress == 200 ) printf("%c/",BACKSPACE);
   if (progress == 300 ) printf("%c-",BACKSPACE);
   if (progress == 400 ) printf("%c\\",BACKSPACE);
   if (progress == 500 ) {
      progress=0;
   }
}

void printhash(char *msg, unsigned char *bhash)
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
    printf("%s : %s\n", msg, ascii_hash);
    free(ascii_hash);
}

void usage(char *name)
{
    printf("Usage   : %s [-o] [-f] -c /path_to_config.cfg\n", name);
    printf("        : -o Optimize the tokyocabinet databases.\n");
    printf("        :    This operation requires enough free space to contain a full copy of the database!\n");
    printf("        :    Optimizing the database is advised after a crash but often we can do without.\n");
    printf("        : -f Start fsck without delay, lessfs is not mounted.\n");
    printf("Version : %s\n",VERSION);
    exit(-1);
}

DBT *fscheck_block_exists(INOBNO inobno)
{
    DBT *data = NULL;
    FUNC;
    data = search_dbdata(dbb, &inobno, sizeof(INOBNO));
    return data;
}

void purge_dbb_beyond(INOBNO *inobno)
{
    char *asc_hash = NULL;
    char *key, *value;
    int size;
    int vsize;
    INOBNO inobnocur;

    printf("purge_dbb_beyond : purge fileblock metadata after blocknr %llu\n",inobno->blocknr);
    /* traverse records */
    tchdbiterinit(dbb);
    while ((key = tchdbiternext(dbb, &size)) != NULL) {
        value = tchdbget(dbb, key, size, &vsize);
        memcpy(&inobnocur.inode, key, sizeof(unsigned long long));
        memcpy(&inobnocur.blocknr, key + sizeof(unsigned long long),
               sizeof(unsigned long long));
        if ( inobno->inode == inobnocur.inode ) {
           if ( inobnocur.blocknr > inobno->blocknr ) {
              printf("delete reference %llu-%llu\n",inobnocur.inode,inobnocur.blocknr);
              tchdbout(dbb,&inobnocur,sizeof(INOBNO));
// Verify dbu in this case.
           }
        }
        free(asc_hash);
        free(value);
        free(key);
    }
}

void get_or_set_dbu(DBT *hash)
{
   unsigned long long inuse;

   inuse=getInUse(hash->data);
   if ( 0 == inuse ) {
     printhash("Used hash without reference in blockusage data, reset to 1",hash->data);
     inuse++;
     update_inuse(hash->data,inuse);
   } 
}


void file_get_or_set_dbu(DBT *hash)
{
   INUSE *inuse;

   if ( 0 == memcmp(config->nexthash, hash->data, config->hashlen)){
        printf("got it\n");
        return; // Skip the nextoffset hash
   }
   inuse=file_get_inuse(hash->data);
   if ( NULL == inuse ) {
     printhash("Used hash without reference in blockusage",hash->data);
   } else {
     if ( inuse->offset + inuse->size  > detected_size ) detected_size=inuse->offset + inuse->size;
   }
}

void check_inode_structure(DDSTAT *ddstat)
{
   INOBNO inobno;
   bool found=0;
   DBT *data;
   DBT *blockdata;
   DBT *ddbuf;

   unsigned long long real_size;

   inobno.blocknr=0;
   inobno.inode=ddstat->stbuf.st_ino;

   while (1){
     data=fscheck_block_exists(inobno); 
     if ( NULL != data ) {
        blockdata=search_dbdata(dbdta, data->data, data->size); 
        if ( NULL == blockdata ) {
           printf("inode %llu-%llu\n",inobno.inode,inobno.blocknr);
           inobno.blocknr--;
           printhash ("hash not found, file is truncated",data->data); 
           purge_dbb_beyond(&inobno);
           break;
        }
        get_or_set_dbu(data);
        DBTfree(blockdata);
        DBTfree(data);
        found=1;
     } else break;
     inobno.blocknr++;
   }
   real_size=BLKSIZE * inobno.blocknr;
   if ( found  && real_size>ddstat->stbuf.st_size+BLKSIZE ) {
     printf("inode %llu size %llu mismatch, restore size to %llu bytes\n",(unsigned long long)ddstat->stbuf.st_ino,(unsigned long long)ddstat->stbuf.st_size,real_size);
     ddstat->stbuf.st_size=real_size;
     ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename, ddstat->real_size); 
     bin_write_dbdata(dbp, &inobno.inode,
                      sizeof(unsigned long long), (void *) ddbuf->data,
                      ddbuf->size);
     DBTfree(ddbuf);
   }
   return;
}

void file_check_inode_structure(DDSTAT *ddstat)
{
   INOBNO inobno;
   bool found=0;
   DBT *data;
   DBT *blockdata;
   DBT *ddbuf;

   unsigned long long real_size;

   inobno.blocknr=0;
   inobno.inode=ddstat->stbuf.st_ino;

   while (1){
     data=fscheck_block_exists(inobno);
     if ( NULL != data ) {
        blockdata=file_tgr_read_data(data->data);
        if ( NULL == blockdata ) {
           printf("inode %llu-%llu\n",inobno.inode,inobno.blocknr);
           inobno.blocknr--;
           printhash ("hash not found, file is truncated",data->data);
           purge_dbb_beyond(&inobno);
           break;
        }
        file_get_or_set_dbu(data);
        DBTfree(blockdata);
        DBTfree(data);
        found=1;
     } else break;
     inobno.blocknr++;
   }
   real_size=BLKSIZE * inobno.blocknr;
   if ( found  && real_size>ddstat->stbuf.st_size+BLKSIZE ) {
     printf("inode %llu size %llu mismatch, restore size to %llu bytes\n",(unsigned long long)ddstat->stbuf.st_ino,(unsigned long long)ddstat->stbuf.st_size,real_size);
     ddstat->stbuf.st_size=real_size;
     ddbuf = create_ddbuf(ddstat->stbuf, ddstat->filename, real_size);
     bin_write_dbdata(dbp, &inobno.inode,
                      sizeof(unsigned long long), (void *) ddbuf->data,
                      ddbuf->size);
     DBTfree(ddbuf);
   }
   return;
}

int find_inode(unsigned long long inode)
{
    BDBCUR *cur;
    char *key, *value;
    int size;
    unsigned long long dir;
    unsigned long long ent;
    int res=0;

    /* traverse records */
    cur = tcbdbcurnew(dbdirent);
    tcbdbcurfirst(cur);
    while ((key = tcbdbcurkey2(cur)) != NULL) {
        memcpy(&dir, key, sizeof(dir));
        value = tcbdbcurval(cur, &size);;
        if (value) {
            memcpy(&ent, value, sizeof(ent));
            if ( inode == ent ) res=1;
            free(value);
        }
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    return(res);
}

/* return 1 when the symlink has no reference */
int relink_symlink(DDSTAT *ddstat)
{
    int ret=1;
    DBT *data;

    printf("Moving orphaned symlink inode %llu to lost_found\n",(unsigned long long)ddstat->stbuf.st_ino);
    /* traverse records */
    data=search_dbdata(dbs,&ddstat->stbuf.st_ino,sizeof(unsigned long long));
    if ( NULL != data ) {
      DBTfree(data);
      ret=0;
    }
    return(ret);
}

/* return 1 when the hardlink has no reference */
int relink_hardlink(DDSTAT *ddstat)
{
    BDBCUR *cur;
    int has_no_reference=0;

    /* traverse records */
    cur = tcbdbcurnew(dbl);
    if (!tcbdbcurjump(cur, (char *) &ddstat->stbuf.st_ino, sizeof(unsigned long long))
        && tcbdbecode(dbdirent) != TCESUCCESS) {
        has_no_reference=1;
    }
    tcbdbcurdel(cur);
    return(has_no_reference);
}

int check_inode_orphaned(DDSTAT *ddstat)
{
   int error=0;
   int ref=0;
   unsigned long long inode=0;
    
   inode=ddstat->stbuf.st_ino;
   if ( ddstat->stbuf.st_ino != lafinode ) {
      error=find_inode(inode); 
      if ( error == 0 ) {
         if ( !S_ISDIR(ddstat->stbuf.st_mode)) {
            if (S_ISLNK(ddstat->stbuf.st_mode)){
               ref=relink_symlink(ddstat);
            }
            if ( ddstat->stbuf.st_nlink > 1 ) {
               ref=relink_hardlink(ddstat);
            }
            if (!ref ) {
               printf("Moving inode orphaned inode %llu to lost+found\n", inode);
               btbin_write_dup(dbdirent, &lafinode, sizeof(unsigned long long),
                            &inode, sizeof(unsigned long long));
            } else error=1;
         } else error=1;
      } else error=0;
   }
   return(error);
}

int lost_mkdir(const char *path)
{
    unsigned long long inode=0;
    char *rdir;
    char *pdir;
    int res;

    FUNC;
    inode=get_next_inode();
    write_file_ent(path, inode, S_IFDIR | 0755, NULL, 0);
    rdir = as_sprintf("%s/.", path);
    inode=get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    rdir = as_sprintf("%s/..", path);
    inode=get_next_inode();
    write_file_ent(rdir, inode, S_IFDIR | 0755, NULL, 0);
    free(rdir);
    /* Change ctime and mtime of the parentdir Posix std posix behavior */
    pdir = s_dirname((char *) path);
    res = update_parent_time(pdir,1);
    free(pdir);
    return (res);
}

void search_and_delete_dbdirent(DDSTAT *ddstat)
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
            if ( ent == ddstat->stbuf.st_ino) {
               printf("Delete %llu:%llu\n",dir,ent);
               btdelete_curkey(dbdirent, &dir,
                             sizeof(unsigned long long), &ent,
                             sizeof(unsigned long long)); 
            }
            free(value);
        }
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);

}

void check_inodes()
{
    char *key, *value;
    int size;
    int ksize;
    DDSTAT *ddstat;
    DBT *data;
    unsigned long long inode;
    char *nfi = "NFI";
    CRYPTO *crypto;
    struct stat stbuf;
    char *blockdatadir;

    if (NULL == config->blockdatabs) {
        blockdatadir = s_dirname(config->blockdata);
        stat(blockdatadir, &stbuf);
        free(blockdatadir);
    } else {
        stat(config->blockdata, &stbuf);
    }
    /* traverse records */
    tchdbiterinit(dbp);
    while ((key = tchdbiternext(dbp, &ksize)) != NULL) {
        show_progress();
        if (0 == memcmp(key, nfi, 3)) {
            value = tchdbget(dbp, key, strlen(key), &size);
            memcpy(&inode, value, sizeof(unsigned long long));
            free(value);
        } else {
            memcpy(&inode, key, sizeof(unsigned long long));
            data = search_dbdata(dbp, &inode, sizeof(unsigned long long));
            if (inode == 0) {
                crypto = (CRYPTO *) data->data;
            } else {
                ddstat = value_to_ddstat(data);
                if ( 0 == check_inode_orphaned(ddstat)) {
                   if (S_ISREG(ddstat->stbuf.st_mode)) {
                      if ( NULL != config->blockdatabs ) { 
                        check_inode_structure(ddstat);   
                      } else {
                        file_check_inode_structure(ddstat);   
                      }    
                   }
                } else {
                   printf("Deleting corrupted inode %llu\n",(unsigned long long)ddstat->stbuf.st_ino);
                   search_and_delete_dbdirent(ddstat);
                   delete_key(dbp, key, ksize);
                }
                ddstatfree(ddstat);
            }
            DBTfree(data);
        }
        free(key);
    }

}

void check_orphaned_data_blocks()
{
    char *key;

    /* traverse records */
    tchdbiterinit(dbdta);
    while ((key = tchdbiternext2(dbdta)) != NULL) {
        if ( 0 == check_inuse((unsigned char *)key)) {
           printhash("Deleting orphaned hash",(unsigned char *)key);
           if (!tchdbout(dbdta, key, config->hashlen)) {
              die_syserr();
           }
        }
        free(key);
    }
}

int check_directory_has_parent(unsigned long long inode)
{
    BDBCUR *cur;
    char *key, *value;
    int size;
    unsigned long long dir;
    unsigned long long ent;
    int hasparent=0;

    /* traverse records */
    cur = tcbdbcurnew(dbdirent);
    tcbdbcurfirst(cur);
    while ((key = tcbdbcurkey2(cur)) != NULL) {
        memcpy(&dir, key, sizeof(dir));
        value = tcbdbcurval(cur, &size);;
        if (value) {
            memcpy(&ent, value, sizeof(ent));
            if ( inode == ent ) hasparent=1;
            free(value);
        }
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
    return(hasparent);
}

void check_directory_structure()
{
    BDBCUR *cur;
    char *key, *value;
    int size;
    int hasparent;
    unsigned long long dir;
    unsigned long long lastdir=0;
    unsigned long long ent;
    int multi=0;
    DBT *data;
    

    /* traverse records */
recheck:
    cur = tcbdbcurnew(dbdirent);
    tcbdbcurfirst(cur);
    while ((key = tcbdbcurkey2(cur)) != NULL) {
        show_progress(); 
        memcpy(&dir, key, sizeof(dir));
        if ( lastdir == dir ) {
           if ( multi == 2 ) {
              tcbdbcurnext(cur);
              continue;
           } else {
              multi=1;
           }
        } else multi=0;
        value = tcbdbcurval(cur, &size);;
        if (value) {
            memcpy(&ent, value, sizeof(ent));
            data = search_dbdata(dbp, &ent, sizeof(unsigned long long));
            if (NULL == data) {
                printf("%ccheck_directory_structure : delete inode %llu present in dbdirent but not found in dbp.\n", BACKSPACE,ent);
                btdelete_curkey(dbdirent, &dir, sizeof(unsigned long long),
                                &ent, sizeof(unsigned long long));
                free(value);
                free(key);
                tcbdbcurdel(cur);
                goto recheck;
            } 
            DBTfree(data);
            free(value);
            if ( multi == 1 ) {
               multi++;
               if ( dir > 1 ) { // Skip the root directory.
               // This is a directory, check if it is linked.
                  hasparent=check_directory_has_parent(dir);
                  if ( hasparent == 0 ) {
                     printf("Directory with inode number %llu is orphaned, relink to lost+found\n", dir);
                     btbin_write_dup(dbdirent, &lafinode, sizeof(unsigned long long),
                            &dir, sizeof(unsigned long long));
                  }
               }
            }
        }
        lastdir=dir;
        free(key);
        tcbdbcurnext(cur);
    }
    tcbdbcurdel(cur);
}


int common_check()
{
    int pcount=1;
    int error;
    int try=0;
    struct stat stbuf;
    char *dirstr;

    if ( chkoptions.optimizetc == 1 ){
       printf( "Phase %i : Running optimize on the databases. ",pcount);
       tc_defrag();
       pcount++;
    }
    error=dbstat("/lost+found",&stbuf);
    if ( error == -ENOENT ) {
       lost_mkdir("/lost+found");
       error=dbstat("/lost+found",&stbuf);
    }
    while ( !S_ISDIR(stbuf.st_mode)) {
       show_progress(); 
       printf("Someone silly (YOU) created lost+found as a regular file.\n");
       dirstr=as_sprintf("/lost+found_%i",try);
       error=dbstat(dirstr,&stbuf);
       if ( -ENOENT == error ) {
          lost_mkdir(dirstr);
          error=dbstat(dirstr,&stbuf);
          free(dirstr);
          break;
       }
       free(dirstr);
       try++;
       if ( try > 3 ) {
         printf("Stupidity count overflow.\n");
         exit(EXIT_USAGE);
       }
    }
    lafinode=stbuf.st_ino;
    printf( "%c \nPhase %u : Check directory structure.\n",BACKSPACE,pcount);
    check_directory_structure();
    pcount++;
    printf( "%cPhase %u : Check for orphaned inodes.\n",BACKSPACE, pcount);
    check_inodes();
    pcount++;
    return(pcount);
}

void lessfsck_tc()
{
    int pcount=common_check();
    printf("%cPhase %u : Check for orphaned data blocks.\n",BACKSPACE,pcount);
    check_orphaned_data_blocks();
    pcount++;
}

void lessfsck_file_io()
{
    unsigned long long rsize;
    struct stat stbuf;
    common_check();
    if (-1 == stat(config->blockdata, &stbuf) ) die_dataerr("%s does not exist.\n",config->blockdata);
    if ( stbuf.st_size > nextoffset ) {
       rsize=round_512(nextoffset);       
       printf("%cFree %llu orphaned bytes.\n",BACKSPACE,nextoffset-rsize);
       if ( -1 == ftruncate(fdbdta, rsize)) die_dataerr("Failed to truncate file %s to size %llu",config->blockdata,rsize);
    }
}

int get_opts(int argc, char *argv[])
{

    int c;

    chkoptions.optimizetc=0; 
    chkoptions.fast=0; 
    chkoptions.configfile=NULL;
    while ((c = getopt (argc, argv, "foc:")) != -1)
      switch (c)
        {
        case 'o':
          chkoptions.optimizetc=1;
          break;
        case 'c':
          if (optopt == 'c')
              printf ( "Option -%c requires a lessfs configuration file as argument.\n", optopt);
          else 
              chkoptions.configfile=optarg;
          break;
        case 'f':
          chkoptions.fast=1;
          break;
        default:
          abort ();
        }
    return 0;
}



int main(int argc, char *argv[])
{
    char *dbg = NULL;
#ifdef ENABLE_CRYPTO
    int rnd;
    char *ckpasswd;
    char *p;
#endif
    if (argc < 2)
        usage(argv[0]);

    debug=0;
    setvbuf(stdout, (char*)NULL, _IONBF, 0);
    get_opts(argc,argv);
    if ( NULL == chkoptions.configfile ) {
        usage(argv[0]);
    }
    if (-1 == r_env_cfg(chkoptions.configfile))
        usage(argv[0]);
    parseconfig(0);
    dbg = getenv("DEBUG");
    if (NULL != dbg)
        debug = atoi(dbg);

    if ( 0 == chkoptions.fast ) {
       printf("Running lessfsck on a mounted filesystem will corrupt the databases.\n");
       printf("Press ctrl-c within 5 secondes when you are not sure that the filesystem is unmounted.\n");
       sleep(5);
    }
    BLKSIZE=get_blocksize();
    if ( NULL != config->blockdatabs ){
       printf("**************************************************\n");
       printf("* Running lessfsck on a tc data store.           *\n");
       printf("**************************************************\n");
       lessfsck_tc();
    } else {
       printf("**************************************************\n");
       printf("* Running lessfsck on a file_io data store.      *\n");
       printf("**************************************************\n");
       lessfsck_file_io();
    }
    printf("\nDone.\n");
    clear_dirty();
    tc_close(0);
#ifdef ENABLE_CRYPTO
    if (config->encryptdata) {
        free(config->passwd);
        free(config->iv);
    }
#endif
    free(config);
    exit(0);
}
