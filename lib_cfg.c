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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "lib_cfg.h"
#include "lib_log.h"
#include "lib_safe.h"
#include "lib_str.h"
#include "retcodes.h"

int r_env_cfg(char *configfile)
{
    FILE *config;
    char *buf;
    char *token;
    char *value;

    config = s_fopen(configfile, "r");
    while (1) {
        buf=s_fgets(1023, config); 
        if (feof(config))
            break;
        if (0 != unrem(buf)) {
            if (NULL == (value = strchr(buf, '='))) {
                free(buf);
                continue;
            }
            token = buf;
            *value = 0;
            value++;
            trim(token);
            trim(value);
            //LINFO("setenv |%s|=|%s|\n", token, value);
            if (-1 == (setenv(token, value, 1))) {
                LFATAL("Setenv failed, out of resources.\n");
                exit(-1);
            }
        }
        free(buf);
    }
    fclose(config);
    return (0);
}


char *read_val(char *token)
{
    char *a;
    a = getenv(token);
    if (NULL == a) {
        LFATAL("Could not read %s\n.", token);
        exit(EXIT_CONFIG);
    }
    LDEBUG("%s=%s\n", token, a);
    return a;
}
