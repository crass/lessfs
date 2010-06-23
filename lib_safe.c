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
#define _XOPEN_SOURCE 500
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef LFATAL
#include "lib_log.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include "retcodes.h"
#include "lib_safe.h"

/* Standard read and write routines */

int s_read(int fd, unsigned char *buf, int len)
{
    int total;
    int thistime;

    for (total = 0; total < len;) {
        thistime = read(fd, buf + total, len - total);

        if (thistime < 0) {
            if (EINTR == errno || EAGAIN == errno)
                continue;
            return -1;
        } else if (thistime == 0) {
            /* EOF, but we didn't read the minimum.  return what we've read
             * so far and next read (if there is one) will return 0. */
            return total;
        }
        total += thistime;
    }
    return total;
}

int s_pread(int fd, void *buf, size_t len, off_t off)
{
    int total;
    int thistime;
    off_t thisoffset;

    thisoffset = off;
    for (total = 0; total < len;) {
        thistime = pread(fd, buf + total, len - total, thisoffset);

        if (thistime < 0) {
            if (EINTR == errno || EAGAIN == errno)
                continue;
            return -1;
        } else if (thistime == 0) {
            /* EOF, but we didn't read the minimum.  return what we've read
             * so far and next read (if there is one) will return 0. */
            return total;
        }
        total += thistime;
        thisoffset += total;
    }
    return total;
}

int s_write(int fd, const unsigned char *buf, int len)
{
    int total;
    int thistime;

    for (total = 0; total < len;) {
        thistime = write(fd, buf + total, len - total);

        if (thistime < 0) {
            if (EINTR == errno || EAGAIN == errno)
                continue;
            return thistime;    /* always an error for writes */
        }
        total += thistime;
    }
    return total;
}

int s_pwrite(int fd, const void *buf, size_t len, off_t off)
{
    int total;
    int thistime;
    off_t thisoff;

    thisoff = off;
    for (total = 0; total < len;) {
        thistime = pwrite(fd, buf + total, len - total, thisoff);

        if (thistime < 0) {
            if (EINTR == errno || EAGAIN == errno)
                continue;
            return thistime;    /* always an error for writes */
        }
        total += thistime;
        thisoff += total;
    }
    return total;
}


void tstamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    LDEBUG("Entering function : %s : %lu:%lu\n", function, tv.tv_sec,
           tv.tv_usec);
}

void estamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    LDEBUG("Exit function : %s : %lu:%lu\n", function, tv.tv_sec,
           tv.tv_usec);
}

void exitFunc()
{
    static int breekijzer = 0;
    pid_t apid;

    apid = getpid();
    if (0 == breekijzer) {
        kill(apid, SIGUSR1);
        breekijzer++;
    } else
        exit(EXIT_SYSTEM);
}

void *s_malloc(size_t size)
{
    void *retval;

    retval = malloc(size);
    if (!retval)
        ERRHANDLE("Out of memory : malloc failed on alloc %lu bytes.\n",
                  (unsigned long) size);
    return retval;
}

void *s_zmalloc(size_t size)
{
    void *retval;

    retval = malloc(size);
    if (!retval)
        ERRHANDLE("Out of memory : malloc failed on alloc %lu bytes.\n",
                  (unsigned long) size);
    memset(retval,0,size);
    return retval;
}

char *s_fgets(int size, FILE *stream)
{
   char *s;
   s=s_malloc(size);
   if ( NULL == fgets(s, size, stream)) {
      if ( !feof(stream)) {
        ERRHANDLE("fgets failed on reading %i bytes : %s.\n", size, strerror(errno));
      }
   }
   return(s);
}

int s_link(const char *oldpath, const char *newpath)
{
    int result;

    result = link(oldpath, newpath);
    if (-1 == result) {
        ERRHANDLE("Could not link %s to %s\n", oldpath, newpath);
    }
    return (result);
}

int s_unlink(const char *ppath)
{
    int result;

    result = unlink(ppath);
    if (-1 == result) {
        ERRHANDLE("Could not unlink %s\n", ppath);
    }
    return (result);
}

void s_fputs(const char *s, FILE * stream)
{
    int result;

    result = fputs(s, stream);
    if (result == EOF)
        ERRHANDLE("Disk write error on s_fputs.\n");
    return;
}

char *s_strdup(const char *s)
{
    char *retval;
    if (s == NULL)
        return NULL;
    retval = strdup(s);
    if (!retval)
        ERRHANDLE("Out of memory : strdup failed.\n");
    return retval;
}

int s_chdir(const char *chpath)
{
    int result;

    result = chdir(chpath);
    if (-1 == result)
        ERRHANDLE("Failed to chdir to : %s\n", chpath);
    return result;
}

FILE *s_fopen(char *path, char *mode)
{
    FILE *retval;

    retval = fopen(path, mode);
    if (!retval)
        ERRHANDLE("fopen %s failed.\n", path);
    return retval;
}

int s_open(const char *pathname, int flags)
{
    int retval;
    if ((retval = open(pathname, flags)) == -1)
        ERRHANDLE("open %s failed\n", pathname);
    return retval;
}

int s_open2(const char *pathname, int flags, mode_t mode)
{
    int retval;
    if ((retval = open(pathname, flags, mode)) == -1)
        ERRHANDLE("open %s failed : %s", pathname, strerror(errno));
    return retval;
}

void *s_realloc(void *ptr, size_t size)
{
    void *retval;
    retval = realloc(ptr, size);

    if (!retval)
        ERRHANDLE("Out of memory : realloc failed.\n");
    return retval;
}

char *as_strcat(char *dest, const char *src)
{
    int srclen;
    int destlen;
    char *retstr = NULL;

    srclen = strlen(src);
    destlen = strlen(dest);

    retstr = s_malloc(srclen + destlen + 1);
    memset(retstr, 0, srclen + destlen + 1);
    memcpy(retstr, dest, destlen);
    memcpy(retstr + destlen, src, srclen);

    return (retstr);
}

char *as_strarrcat(const char **strarr, ssize_t count)
{
    int totallen = 0;
    int i;
    char *retstr = NULL, *curpos;

    for (i = 0; i < count; i++) {
        totallen += strlen(strarr[i]);
    }

    curpos = retstr = s_zmalloc(totallen + 1);
    for (i = 0; i < count; i++) {
        strcpy(curpos, strarr[i]);
        curpos += strlen(strarr[i]);
    }

    return retstr;
}

void *as_sprintf(const char *fmt, ...)
{
    /* Guess we need no more than 100 bytes. */
    int n, size = 100;
    void *p;
    va_list ap;
    p = s_malloc(size);
    while (1) {
        /* Try to print in the allocated space. */
        va_start(ap, fmt);
        n = vsnprintf(p, size, fmt, ap);
        va_end(ap);
        /* If that worked, return the string. */
        if (n > -1 && n < size)
            return p;
        /* Else try again with more space. */
        if (n > -1)             /* glibc 2.1 */
            size = n + 1;       /* precisely what is needed */
        else                    /* glibc 2.0 */
            size *= 2;          /* twice the old size */
        p = s_realloc(p, size);
    }
}

int compare_elements(const void **p1, const void **p2)
{
    return strcoll(*p1, *p2);
}

char **s_srtOpenDir(char *processDir)
{
    DIR *dp = NULL;
    struct dirent *entry;
    int pcount = 0;
    int len;
    unsigned int allocated = 0;
    char **sortme;
    struct stat stbuf;

    if (NULL == (dp = (opendir(processDir)))) {
        ERRHANDLE("opendir %s failed in s_srtOpendir.\n", processDir);
    }
    pcount = 0;
    allocated = 0;
    sortme = (char **) s_malloc(sizeof(char *));
    while (NULL != (entry = readdir(dp))) {
        if (-1 == stat(entry->d_name, &stbuf)) {
            continue;
        }
        if (S_ISDIR(stbuf.st_mode)) {
            continue;
        }
        len = strlen(entry->d_name) + 1;
        allocated = allocated + len;
        sortme[pcount] = s_malloc(len);
        sprintf(sortme[pcount], "%s", entry->d_name);
        pcount++;
        len = allocated + sizeof(char *);
        allocated = len;
        sortme = (char **) s_realloc(sortme, allocated);
    }
    closedir(dp);
    sortme[pcount] = NULL;
    qsort(sortme, pcount, sizeof(char *), (void *) compare_elements);
    return sortme;
}

int dirCnt(char *processDir)
{
    int count = 0;
    DIR *dp = NULL;
    struct dirent *entry;
    struct stat stbuf;

    if (NULL == (dp = (opendir(processDir)))) {
        ERRHANDLE("opendir %s failed in dirCnt\n", processDir);
    }
    while (NULL != (entry = readdir(dp))) {
        if (-1 == stat(entry->d_name, &stbuf)) {
            continue;
        }
        if (S_ISDIR(stbuf.st_mode)) {
            continue;
        }
        count++;
    }
    closedir(dp);
    return (count);
}

char *s_basename(char *path)
{
    char *tmpstr;
    char *rdir;
    char *retstr;
    tmpstr = s_strdup(path);
    rdir = basename(tmpstr);
    retstr = s_strdup(rdir);
    free(tmpstr);
    return retstr;
}

char *s_dirname(char *path)
{
    char *tmpstr;
    char *rdir;
    char *retstr;

    if (NULL == path)
        return NULL;
    tmpstr = s_strdup(path);
    rdir = dirname(tmpstr);
    retstr = s_strdup(rdir);
    free(tmpstr);
    return retstr;
}

int mkpath(const char *s, mode_t mode){
        char *q, *r = NULL, *path = NULL, *up = NULL;
        int rv;

        rv = -1;
        if (strcmp(s, ".") == 0 || strcmp(s, "/") == 0)
                return (0);

        path=s_strdup(s);
        q = s_strdup(s);
        r = s_dirname(q);
        up = s_strdup(r);
        if ((mkpath(up, mode) == -1) && (errno != EEXIST))
                goto out;
        if ((mkdir(path, mode) == -1) && (errno != EEXIST))
                rv = -1;
        else
                rv = 0;
out:
        if (up != NULL)
                free(up);
        free(q);
        free(path);
        free(r);
        return (rv);
}
