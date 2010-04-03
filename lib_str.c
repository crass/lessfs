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

#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include "lib_safe.h"


/******************************************************
* Procedure trim()                                    *
* Doel : Ontdoe een regel van spaties,tabs,nl,cr      *
* Input: char naam logbestand                         *
* Output: filehandler anders -1                       *
******************************************************/
void trim(char *regel)
{
    int tel;
    int einde, lengte;
    char *tmpstr;

    if (regel == NULL)
        return;                 /* Een lege string is niet te trimmen */

    lengte = strlen(regel);
    tmpstr = s_strdup(regel);

    for (tel = 0; tel <= lengte; tel++) {
        if (regel[tel] != ' ' && regel[tel] != '\t')
            break;
    }

    einde = lengte;
    if (einde == 0) {
        regel[0] = 0;
        free(tmpstr);
        return;                 /* Na het begin v.d. regel trimmen niets over */
    }

    while (einde > 0) {
        einde--;
        if (regel[einde] != ' ' && regel[einde] != '\t'
            && regel[einde] != '\n' && regel[einde] != '\r')
            break;
    }

    lengte = einde - tel + 1;
    memcpy(&regel[0], &tmpstr[tel], lengte);
    regel[lengte] = 0;
    free(tmpstr);
    return;
}

void replacechar(char *buffer, char zoek, char vervang)
{
    char *p;
    p = buffer;
    while (*buffer != 0) {
        if (*buffer != zoek) {
            *p = *buffer;
            p++;
        } else {
            p[0] = vervang;
            p++;
        }
        buffer++;
    }
    *p = 0;
}

/***********************************************************************
Procedure stripchar
Doel : Verwijderd een %c uit een %s
***********************************************************************/
void stripchar(char *a, char c)
{
    char *p;
    p = a;
    while (*a != 0) {
        if (*a != c) {
            *p = *a;
            p++;
        }
        a++;
    }
    *p = 0;
}

/***********************************************************************
Procedure lcase
Doel : Convert een string naar lowercase
***********************************************************************/
void lcase(char *convert)
{
    while (*convert != 0) {
        *convert = tolower(*convert);
        convert++;
    }
}

/***********************************************************************
Procedure ucase
Doel : Convert een string naar uppercase
***********************************************************************/
void ucase(char *convert)
{
    while (*convert != 0) {
        *convert = toupper(*convert);
        convert++;
    }
}

/***********************************************************************
Procedure unrem
Invoer regel[]
Uitvoer regel zonder remark's
return lengte ge 'unremde' string
***********************************************************************/
int unrem(char *regel)
{
    char *c;

    c = strchr(regel, '#');
    if (c != NULL)
        c[0] = 0;
    return (strlen(regel));
}
