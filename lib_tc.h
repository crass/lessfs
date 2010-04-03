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
#define die_dberr(f...) { LFATAL(f); exit(EXIT_DBERR); }
#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }
#define die_syserr() { LFATAL("Fatal system error : %s",strerror(errno)); exit(EXIT_SYSTEM); }
#define MAX_POSIX_FILENAME_LEN 256
#define MAX_FUSE_BLKSIZE 131072
#define BMWLEN 224
#define METAQSIZE 2048

typedef unsigned long long int word64;
typedef unsigned long word32;
typedef unsigned char byte;
void tiger(byte *, word64, word64 *);

typedef struct {
    unsigned long long inode;
    unsigned long long blocknr;
} INOBNO;

typedef struct {
    //unsigned int snapshotnr;
    unsigned long long dirnode;
    unsigned long long inode;
} DINOINO;

typedef struct {
    unsigned long size;
    unsigned char *data;
} DBT;

typedef struct {
    struct stat stbuf;
    char filename[MAX_POSIX_FILENAME_LEN];
} DDSTAT;

typedef struct {
    char passwd[64];
    char iv[8];
} CRYPTO;

typedef struct {
    unsigned long long blocknr;
    unsigned char blockdata[MAX_FUSE_BLKSIZE];
} BLKCACHE;

typedef struct {
    struct stat stbuf;
    unsigned int updated;
    unsigned long long blocknr;
    unsigned int opened;
    unsigned long long deduplicated;
    unsigned long long lzo_compressed_size;
    char filename[MAX_POSIX_FILENAME_LEN];
} MEMDDSTAT;

typedef struct {
    compr *compressed;
    const char *blockdata;
    unsigned long long blocknr;
    unsigned int offsetblock;
    size_t bsize;
    unsigned long long inode;
    bool sparse;
    unsigned char *stiger;
    unsigned char *blockfiller;
    unsigned char *buf;
} BLKDTA;

typedef struct {
    unsigned long long offset;
    unsigned long size;
    unsigned char data[MAX_FUSE_BLKSIZE];
} QDTA;

DBT *check_block_exists(INOBNO);
unsigned long long readBlock(unsigned long long, const char *, char *,
                             unsigned long long);
int dbstat(const char *, struct stat *);
void formatfs();
unsigned long long get_next_inode();
void bin_write_dbdata(TCHDB *, void *, int, void *, int);
void asc_write_dbdata(TCHDB *, unsigned char *, unsigned char *);
void mbin_write_dbdata(TCMDB *, void *, int, void *, int);
void dbmknod(const char *, mode_t, char *, dev_t);
void get_global_lock();
void release_global_lock();
void DBTfree(DBT *);
void delete_key(TCHDB *, void *, int);
unsigned long long getInUse(unsigned char *);
void tc_open(bool, bool);
void tc_close(bool);
DBT *search_dbdata(TCHDB *, void *key, int);
char *hash(char *, int);
void update_inuse(unsigned char *, unsigned long long);
void hash_update_filesize(MEMDDSTAT *, unsigned long long);
void update_filesize(unsigned long long, unsigned long long, unsigned int,
                     unsigned long long, bool, unsigned int, unsigned int);
void addBlock(BLKDTA *);
void db_update_block(const char *, unsigned long long,
                     unsigned int, unsigned long long, unsigned long long,
                     unsigned char *);
void write_file_ent(const char *, unsigned long long, mode_t mode, char *,
                    dev_t);
int db_unlink_file(const char *);
int fs_mkdir(const char *, mode_t);
int db_fs_truncate(struct stat *, off_t, char *);
int fs_rmdir(const char *);
unsigned long long get_inode(const char *);
int fs_readdir(const char *, void *, fuse_fill_dir_t, off_t,
               struct fuse_file_info *);
void btasc_curwrite_dbdata(TCBDB *, BDBCUR *, unsigned char *);
void btasc_write_dbdata(TCBDB *, char *, char *);
int fs_link(char *, char *);
int fs_symlink(char *, char *);
int fs_readlink(const char *, char *, size_t);
int fs_rename(const char *, const char *, struct stat);
int fs_rename_link(const char *, const char *, struct stat);
char *fs_search_topdir(char *);
void btbin_write_dbdata(TCBDB *, void *, int, void *, int);
void btbin_curwrite_dbdata(TCBDB *, BDBCUR *, char *, int);
void ddstatfree(DDSTAT *);
DBT *create_ddbuf(struct stat, char *);
DDSTAT *value_to_ddstat(DBT *);
unsigned long long has_nodes(unsigned long long);
void fil_fuse_info(DDSTAT *, void *, fuse_fill_dir_t,
                   struct fuse_file_info *);
void bt_curwrite(TCBDB *, char *, char *);
int bt_entry_exists(TCBDB *, void *, int, void *, int);
DDSTAT *dnode_bname_to_inode(void *, int, char *);
int count_dirlinks(void *, int);
MEMDDSTAT *value_tomem_ddstat(char *, int);
DBT *search_memhash(TCMDB *, void *, int);
DBT *create_mem_ddbuf(MEMDDSTAT *);
void update_filesize_onclose(unsigned long long);
void mdelete_key(TCMDB *, void *, int);
void update_cache(unsigned long long, struct stat *);
int update_stat(char *path, struct stat *);
void memddstatfree(MEMDDSTAT *);
int update_parent_time(char *, int);
void tc_defrag();
void binhash(unsigned char *, int, word64[3]);
unsigned char *sha_binhash(unsigned char *, int);
void dta_mutex_init(int);
void release_dta_lock(int);
void release_write_lock();
void dta_lock(int);
void worker_lock();
void sync_flush_dtaq();
void release_worker_lock();
void release_all_dta_lock();
void all_dta_lock();
void write_lock();
void tiger_lock();
void open_lock();
void release_tiger_lock();
void release_open_lock();
void get_qempty_lock();
void get_hash_lock();
void get_qdta_lock();
void get_moddb_lock();
void get_dbu_lock();
void get_dbb_lock();
void release_dbu_lock();
void release_dbb_lock();
void release_moddb_lock();
void release_hash_lock();
void release_qempty_lock();
void release_qdta_lock();
void wait_io_pending(unsigned long long);
void write_nfi(unsigned long long);
void btbin_write_dup(TCBDB *, void *, int, void *, int);
void *btsearch_keyval(TCBDB *, void *, int, void *, int);
int inode_block_pending(unsigned long long, unsigned long long);
DBT *try_block_cache(unsigned long long, unsigned long long, unsigned int);
void flush_dta_queue();
void add_blk_to_cache(unsigned long long, unsigned long long,
                      unsigned char *);
void qdta(unsigned char *, DBT *);
void comprfree(compr *);
void loghash(char *, unsigned char *);
int try_global_lock();
MEMDDSTAT *inode_meta_from_cache(unsigned long long);
void wait_inode_block_pending(unsigned long long, unsigned long long);
void parseconfig(int);
void checkpasswd(char *);
int btdelete_curkey(TCBDB *, void *, int, void *, int);
void log_fatal_hash(char *, unsigned char *);
int sync_flush_dbu();
int sync_flush_dbb();
void delete_inuse(unsigned char *);
void delete_dbb(INOBNO *);
void write_dbb_to_cache(INOBNO *,unsigned char *);
void clear_dirty();
int get_blocksize();
void brand_blocksize();
int update_filesize_cache(struct stat *, off_t);
int try_open_lock();
int try_write_lock();
int try_tiger_lock();
int try_dbb_lock();
int try_dbu_lock();
int try_moddb_lock();
int try_worker_lock();
int try_qdta_lock();
int try_qempty_lock();
void drop_databases();
void lessfs_trans_stamp();
void lessfs_snap_stamp();
