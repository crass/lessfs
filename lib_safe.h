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
#define ERRHANDLE(f...){ LFATAL(f); exitFunc(); }
void *s_malloc(size_t);
void *s_zmalloc(size_t);
char *s_strdup(const char *);
FILE *s_fopen(char *, char *);
int s_open(const char *, int);
int s_open2(const char *, int, mode_t);
void *s_realloc(void *, size_t);
void *as_sprintf(const char *fmt, ...);
char **s_srtOpenDir(char *);
int dirCnt(char *);
void s_fputs(const char *, FILE *);
int s_chdir(const char *);
int s_link(const char *, const char *);
int s_unlink(const char *);
void exitFunc();
void tstamp();
void estamp();
char *as_strcat(char *, const char *);
char *as_strarrcat(const char **, ssize_t);
int s_read(int, unsigned char *, int);
int s_write(int, const unsigned char *, int);
int s_pwrite(int, const void *, size_t, off_t);
int s_pread(int fd, void *, size_t, off_t);
int mkpath(const char *, mode_t);
char *s_dirname(char *);
char *s_basename(char *);
char *s_fgets(int, FILE *);
