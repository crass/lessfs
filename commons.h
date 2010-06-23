#define MAX_THREADS 1

struct configdata *config;

char *logname;
char *function=__FILE__;
int debug = 5;
int BLKSIZE = 4096;
int max_threads = MAX_THREADS;

extern TCHDB *dbp;
extern TCHDB *dbu;
extern TCHDB *dbb;
extern TCHDB *dbdta;
extern TCHDB *dbs;
extern TCBDB *dbdirent;
extern TCBDB *freelist;
extern TCBDB *dbl;

extern TCTREE *workqtree;
extern TCTREE *delayedqtree;
extern TCTREE *readcachetree;

extern TCTREE *metatree;
extern TCTREE *hashtree;
extern int fdbdta;

extern unsigned long long nextoffset;
extern const char *write_lockedby;
extern const char *global_lockedby;
extern const char *hash_lockedby;
extern const char *meta_lockedby;
