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


#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef ENABLE_CRYPTO
#include<openssl/ssl.h>
#include<openssl/evp.h>
#endif

#include "lib_safe.h"
#include "retcodes.h"
#include "lib_cfg.h"

extern char *logname;
extern char *function;
extern int debug;
extern int BLKSIZE;
extern char *passwd;

#define die_cryptoerr(f...) { LFATAL(f); exit(EXIT_CRYPTOERR); }

typedef struct {
    unsigned long size;
    unsigned char *data;
} DBT;

unsigned char *safepassword()
{
    int len;
    unsigned char *safepasswd;

    len = strlen((char *) config->passwd);
    if (len > 16)
        len = 16;
    safepasswd = s_malloc(16);
    memset(safepasswd, 65, 16);
    memcpy(safepasswd, config->passwd, len);
    return safepasswd;
}

#ifdef ENABLE_CRYPTO
DBT *encrypt(unsigned char *unenc, unsigned long size)
{
    unsigned char *safepasswd;
    EVP_CIPHER_CTX ctx;
    DBT *encoded;
    int olen, tlen;

    FUNC;

    safepasswd = safepassword();
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit(&ctx, EVP_bf_cbc(), safepasswd, config->iv);
    encoded = s_malloc(sizeof(DBT));
    encoded->data = s_malloc(8 + size); //Blowfish can grow 64 bits

    if (EVP_EncryptUpdate(&ctx, encoded->data, &olen, unenc, size) != 1) {
        die_cryptoerr("error in encrypt update\n");
    }

    if (EVP_EncryptFinal(&ctx, encoded->data + olen, &tlen) != 1) {
        die_cryptoerr("error in encrypt final\n");
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    encoded->size = olen + tlen;
    if (encoded->size > 8 + size) {
        die_cryptoerr
            ("Unexpected fatal error : data has grown in size after encryption.\n");
    }
    free(safepasswd);
    EFUNC;
    return encoded;
}

DBT *decrypt(DBT * data)
{
    DBT *decrypted;
    unsigned char *safepasswd;

    int olen, tlen;

    FUNC;
    decrypted = s_malloc(sizeof(DBT));
    decrypted->data = s_malloc(data->size);
    safepasswd = safepassword();

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit(&ctx, EVP_bf_cbc(), safepasswd, config->iv);

    if (EVP_DecryptUpdate
        (&ctx, decrypted->data, &olen, data->data, data->size) != 1) {
        die_cryptoerr("Unexpected fatal error while decrypting.\n");
    }

    if (EVP_DecryptFinal(&ctx, decrypted->data + olen, &tlen) != 1) {
        die_cryptoerr("Unexpected fatal error in decrypt final.\n");
    }
    olen += tlen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    decrypted->size = olen;
    free(safepasswd);
    EFUNC;
    return decrypted;
}
#endif
