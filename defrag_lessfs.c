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
#include "lib_log.h"
#include "lib_safe.h"
#include "lib_cfg.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "commons.h"

#ifdef i386
#define ITERATIONS 30
#else
#define ITERATIONS 500
#endif

u_int32_t db_flags, env_flags;

void usage(char *name)
{
    printf("Usage: %s /path_to_config.cfg\n", name);
    exit(-1);
}

int main(int argc, char *argv[])
{
    char *dbg = NULL;

    if (argc < 2)
        usage(argv[0]);

    dbg = getenv("DEBUG");
    if (NULL != dbg)
        debug = atoi(dbg);

    FUNC;
    if (-1 == r_env_cfg(argv[1]))
        usage(argv[0]);

    parseconfig(0);
    pthread_spin_init(&moddb_spinlock, 0);
    tc_defrag();
    tc_close(1);
    sync();
    exit(0);
}
