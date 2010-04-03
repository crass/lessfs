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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef LZO
#include <lzo/lzoconf.h>
#include <lzo/lzo1a.h>
#include <lzo/lzo_asm.h>
#include <lzo/lzoutil.h>

/* portability layer */
#define WANT_LZO_MALLOC 1
//#include "portab.h"
#include "lib_log.h"
#include "lib_io.h"
#include "lib_safe.h"
#include "lib_lzo.h"

extern char *logname;
extern char *function;
extern int debug;
extern int BLKSIZE;

/* We want to compress the data block at `in' with length `IN_LEN' to
 * the block at `out'. Because the input block may be incompressible,
 * we must provide a little more output space in case that compression
 * is not possible.
 */

#ifndef IN_LEN
#define IN_LEN      (128*1024L)
#endif
#define OUT_LEN     (IN_LEN + IN_LEN / 16 + 64 + 3)

/*************************************************************************
//
**************************************************************************/
void initlzo()
{
    if (lzo_init() != LZO_E_OK) {
        LFATAL("internal error - lzo_init() failed !!!");
        exit(4);
    }
}

compr *lzo_compress(unsigned char *buf, int buflen)
{
    int r;
    lzo_bytep in;
    lzo_bytep out;
    lzo_bytep wrkmem;
    lzo_uint out_len;
    compr *retdata;

    retdata = s_malloc(sizeof(compr));

    in = (lzo_bytep) buf;
    out = (lzo_bytep) lzo_malloc(OUT_LEN);
    wrkmem = (lzo_bytep) lzo_malloc(LZO1A_MEM_COMPRESS);
    if (in == NULL || out == NULL || wrkmem == NULL) {
        LFATAL("out of memory\n");
        exit(3);
    }

    r = lzo1a_compress(in, buflen, out, &out_len, wrkmem);
    if (r != LZO_E_OK) {
        /* this should NEVER happen */
        LFATAL("internal error - compression failed: %d\n", r);
        exit(2);
    }
    /* check for an incompressible block */
    if (out_len >= buflen) {
        // LINFO("This block contains incompressible data.\n");
        retdata->data = s_malloc(buflen);
        memcpy(retdata->data, buf, buflen);
        retdata->size = buflen;
    } else {
        // LDEBUG("Compressed %i bytes to %lu bytes",buflen,(unsigned long)out_len);
        retdata->data = s_malloc(out_len);
        retdata->size = out_len;
        memcpy(retdata->data, out, out_len);
    }
    lzo_free(wrkmem);
    lzo_free(out);
    return retdata;
}

compr *lzo_decompress(unsigned char *buf, int buflen)
{
    int r;
    lzo_bytep in;
    lzo_bytep out;
    lzo_bytep wrkmem;
    lzo_uint out_len = 0;
    lzo_uint in_len = 0;
    compr *retdata;

    FUNC;

    retdata = s_malloc(sizeof(compr));
    in_len = buflen;

    in = (lzo_bytep) buf;
    out = (lzo_bytep) lzo_malloc(BLKSIZE);
    wrkmem = (lzo_bytep) lzo_malloc(LZO1A_MEM_COMPRESS);        //FASTER
    if (in == NULL || out == NULL || wrkmem == NULL) {
        LFATAL("out of memory\n");
        exit(3);
    }

    r = lzo1a_decompress(in, in_len, out, &out_len, NULL);
    if (r != LZO_E_OK) {
        /* this should NEVER happen */
        LFATAL("internal error - decompression failed: %d\n", r);
        exit(22);
    }

    retdata->data = s_malloc(out_len);
    retdata->size = out_len;
    memcpy(retdata->data, out, out_len);
    lzo_free(wrkmem);
    lzo_free(out);
    return retdata;
}
#endif
