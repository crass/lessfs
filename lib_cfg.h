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
struct configdata {
    char *blockdata;
    char *blockdatabs;
    char *blockdata_io_type;
    char *blockusage;
    char *blockusagebs;
    char *dirent;
    char *direntbs;
    char *fileblock;
    char *fileblockbs;
    char *meta;
    char *metabs;
    char *hardlink;
    char *hardlinkbs;
    char *symlink;
    char *symlinkbs;
    char *freelist;
    char *freelistbs;
    char *nexthash;
    unsigned char *commithash;
    char *hash;
    char *lfsstats;
    unsigned char compression;
    unsigned char *iv;
    unsigned char *passwd;
    unsigned long long cachesize;
    unsigned int flushtime;
    unsigned int inspectdiskinterval;
    unsigned int defrag;
    unsigned int relax;
    unsigned int encryptdata;
    unsigned int encryptmeta;
    unsigned int selected_hash;
    int hashlen;
    int transactions;
};
struct configdata *config;

int read_s_cfg(char *cfgfile, char *value, int size);
int read_m_cfg(char *cfgfile, char *value, char *value2, int size);
int r_env_cfg(char *configfile);
char *read_val(char *token);
