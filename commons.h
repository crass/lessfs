extern pthread_spinlock_t moddb_spinlock;
extern pthread_spinlock_t dbu_spinlock;
extern pthread_spinlock_t dbb_spinlock;
extern unsigned int dbu_qcount;
extern unsigned int dbb_qcount;

struct configdata *config;

char *logname;
char *function=__FILE__;
int debug = 5;
int BLKSIZE = 4096;
#define MAX_THREADS 1
int max_threads = MAX_THREADS;
BLKDTA **tdta = NULL;

extern TCHDB *dbp;
extern TCHDB *dbu;
extern TCHDB *dbb;
extern TCHDB *dbdta;
extern TCHDB *dbs;
extern TCBDB *dbdirent;
extern TCBDB *freelist;
extern TCBDB *dbl;
extern TCMDB *dbcache;
extern TCMDB *dbdtaq;
extern TCMDB *blkcache;
extern TCMDB *dbum;
extern TCMDB *dbbm;
extern int fdbdta;

BLKDTA *blkdta;

extern unsigned long long nextoffset;
