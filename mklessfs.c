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
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <fuse.h>

#include <tcutil.h>
#include <tchdb.h>
#include <tcbdb.h>
#include <stdlib.h>
#include <stdbool.h>

#include "lib_cfg.h"
#include "lib_safe.h"
#include "lib_str.h"
#include "retcodes.h"
#ifdef LZO
#include "lib_lzo.h"
#else
#include "lib_qlz.h"
#endif
#include "lib_tc.h"
#include "commons.h"

#ifdef ENABLE_CRYPTO
unsigned char *passwd = NULL;
#endif

#define die_dataerr(f...) { LFATAL(f); exit(EXIT_DATAERR); }

struct option_info {
    char *configfile;
    int force;
};
struct option_info mkoptions;

void usage(char *name)
{
    printf("Usage: %s /path_to_config.cfg\n", name);
    printf("     : %s [-f] -c /path_to_config.cfg\n\n", name);
    printf("-c Path and name of the configuation file\n");
    printf("-f Overwrite existing databases and create directories when needed\n");
    printf("-h Displays this usage message\n");
    exit(-1);
}

int get_opts(int argc, char *argv[])
{

    int c;

    mkoptions.force=0;
    mkoptions.configfile=NULL;
    while ((c = getopt (argc, argv, "hfc:")) != -1)
      switch (c)
        {
        case 'c':
          if (optopt == 'c')
              printf ( "Option -%c requires a lessfs configuration file as argument.\n", optopt);
          else
              mkoptions.configfile=optarg;
          break;
        case 'f':
          mkoptions.force=1;
          break;
        case 'h':
          usage(argv[0]);
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

    get_opts(argc,argv);
    if ( NULL == mkoptions.configfile ) mkoptions.configfile=argv[1];  
    if (-1 == r_env_cfg(mkoptions.configfile))
        usage(argv[0]);
    dbg = getenv("DEBUG");
    if (NULL != dbg)
        debug = atoi(dbg);
    if (mkoptions.force == 1 ) {
       parseconfig(2);
    } else parseconfig(1);
    config->encryptdata = 0;
    config->passwd = NULL;
    config->iv = NULL;
#ifdef ENABLE_CRYPTO
    config->iv = s_malloc(8);
    memset(config->iv, 0, 8);
    config->encryptdata = 0;
    p = read_val("ENCRYPT_DATA");
    if (NULL != p) {
        if (0 == strcasecmp(p, "ON"))
            config->encryptdata = 1;
        /*if (config->encryptdata) {
            if (NULL == config->blockdatabs) {
                fprintf(stderr,"Encryption is not supported with file_io\n");
                die_dataerr("Encryption is not supported with file_io");
            }
        }*/
    }
#endif
    config->encryptmeta = 1;
#ifdef ENABLE_CRYPTO
    if (config->encryptdata) {
        rnd = s_open("/dev/random", O_RDONLY);
        if (8 != s_read(rnd, config->iv, 8)){
            die_dataerr("Could not read 8 bytes from /dev/random");
        }
        if ( NULL == getenv("PASSWORD")){
               config->passwd =
                   (unsigned char *) s_strdup(getpass("Password: "));
               ckpasswd = s_strdup(getpass("Re-Enter Password: "));
               if (0 != strcmp((char *) config->passwd, ckpasswd)) {
                   fprintf(stderr, "Password values do not match.\n");
                   exit(EXIT_SYSTEM);
               }
               free(ckpasswd);
        } else {
            config->passwd = s_strdup(getenv("PASSWORD"));
            unsetenv("PASSWORD"); /* Eat it after receiving..*/
        }
        p = getenv("ENCRYPT_META");
        if (NULL != p) {
            if (0 != strcasecmp(p, "ON")) {
                LINFO("Metadata encryption is off");
                config->encryptmeta = 0;
            }
        }
    }
#endif
    config->commithash=thash((unsigned char *)"COMMITSTAMP", strlen("COMMITSTAMP"),1);
    formatfs();
    sync();
#ifdef ENABLE_CRYPTO
    if (config->encryptdata) {
        free(config->passwd);
        free(config->iv);
    }
#endif
    free(config);
    exit(0);
}
