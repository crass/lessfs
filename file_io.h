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
typedef struct {
    unsigned long long offset;
    unsigned long size;
    unsigned long long inuse;
} INUSE;

typedef struct {
    unsigned long long available_blocks;
    unsigned long long offset;
} FLIST;

INUSE *file_get_inuse(unsigned char *);
void add_file_block(BLKDTA *);
unsigned int file_commit_block(unsigned char *, unsigned char *, INOBNO,
                               bool);
void file_sync_flush_dtaq();
void file_partial_truncate_block(struct stat *, unsigned long long,
                                 unsigned int);
int file_unlink_file(const char *);
void file_update_block(const char *, unsigned long long, unsigned int,
                       unsigned long long, unsigned long long,
                       unsigned char *);
unsigned long long file_read_block(unsigned long long, const char *, char *, unsigned long long);
int file_fs_truncate(struct stat *, off_t, char *);
void file_update_inuse(unsigned char *, INUSE *);
DBT *file_tgr_read_data(unsigned char *);
