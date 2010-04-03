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

#include <ctype.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include "lib_log.h"
#include "lib_safe.h"
#include "lib_net.h"
#include "retcodes.h"

extern pid_t mypid;
extern char *logname;
extern char *function;

void die_nomem()
{
    LFATAL("Out of memory\n");
    exit(EXIT_SYSTEM);
}

void exitWriteLine()
{
    LFATAL("writeLine failed in writeHeader.\n");
    exit(EXIT_SYSTEM);
}

/* Reads a string with an arbitrary ending delimiter. */

int readdelimstring(int sec, int sockid, char *buf, int maxlen, char delim)
{
    int count = 0, status;

    while (count <= maxlen) {
        status = timeoutRead(sec, sockid, buf + count, 1);
        if (status < 0)
            return status;
        if (status < 1) {
            return status;
        }
        if (buf[count] == delim) {      /* Found the delimiter */
            buf[count] = 0;
            return 0;
        }
        count++;
    }
    return 0;
}

/* Reads a string from the network, terminated by a null. */

int readstring(int sec, int sockid, char *buf, int maxlen)
{
    return readdelimstring(sec, sockid, buf, maxlen, 0);
}

/* Reads a string terminated by a newline */

int readnlstring(int sec, int sockid, char *buf, int maxlen)
{
    return readdelimstring(sec, sockid, buf, maxlen, '\n');
}

int timeoutRead(int t, int fd, char *b, int l)
{
    int rc = -1;
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = t;
    tv.tv_usec = 0;

    if (select(fd + 1, &fds, NULL, NULL, &tv)) {
      again:
        if ((rc = read(fd, b, l)) < 0) {
            if (errno == EINTR || EAGAIN == errno)
                goto again;
        }
    }
    return (rc);
}

int timeoutWrite(int t, int fd, char *b, int l)
{
    int rc = -1;
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = t;
    tv.tv_usec = 0;

    if (select(fd + 1, NULL, &fds, NULL, &tv)) {
      again:
        if ((rc = write(fd, b, l)) < 0) {
            if (errno == EINTR || EAGAIN == errno)
                goto again;
        }
    }
    return (rc);
}

char *readMsg(int fd)
{
    int bufcount = BUFSIZE;
    int bytes = 0;
    int rc = -1;
    static char *mg_msg, *mg_msg2;

    mg_msg = s_malloc(bufcount);
    mg_msg2 = mg_msg;
    while (1) {
        rc = timeoutRead(30, fd, mg_msg2, 1);
        if (rc < 0)
            return NULL;
        if (rc == 0)
            break;
        bytes = bytes + rc;
        bufcount = bufcount + rc;
        if (NULL == (mg_msg = realloc(mg_msg, bufcount)))
            die_nomem();
        mg_msg2 = mg_msg + bytes;
    }
    mg_msg[bytes] = 0;
    return mg_msg;
}

int resolveproto(const char *proto)
{
    struct protoent *protocol;
    protocol = getprotobyname(proto);
    if (!protocol) {
        LFATAL("resolveproto : getprotobyname failed for %s", proto);
        return -1;
    }

    return protocol->p_proto;
}

static int checkstring(const char *string);

/* checkstring() is a private function used only by this library.  It checks
    the passed string.  It returns false if there are no nonnumeric
    characters  in the string, or true if there are such characters. */

static int checkstring(const char *string)
{
    int counter;
    for (counter = 0; counter < strlen(string); counter++)
        if (!(isdigit(string[counter])))
            return 1;
    return 0;
}

int prototype(const char *proto)
{
    if (strcmp(proto, "tcp") == 0)
        return SOCK_STREAM;
    if (strcmp(proto, "udp") == 0)
        return SOCK_DGRAM;
    return -1;
}

int socketaddr_host(struct sockaddr_in *socketaddr, const char *host)
{
    struct hostent *hostaddr;
    hostaddr = gethostbyname(host);
    if (!hostaddr) {
        LFATAL("socketaddr_host: gethostbyname failed for %s", host);
        return -1;
    }

    memcpy(&socketaddr->sin_addr, hostaddr->h_addr, hostaddr->h_length);
    return 0;
}

int
socketaddr_service(struct sockaddr_in *socketaddr,
                   const char *service, const char *proto)
{
    struct servent *serviceaddr;

    /* Need to allow numeric as well as textual data. */

    /* 0: pass right through. */

    if (strcmp(service, "0") == 0)
        socketaddr->sin_port = 0;
    else {                      /* nonzero port */
        serviceaddr = getservbyname(service, proto);
        if (serviceaddr) {
            socketaddr->sin_port = serviceaddr->s_port;
        } else {                /* name did not resolve, try number */
            if (checkstring(service)) { /* and it's a text name, fail. */
                LFATAL("socketaddr_service no lookup for %s/%s", service,
                       proto);
                return -1;
            }
            if ((socketaddr->sin_port =
                 htons((u_short) atoi(service))) == 0) {
                LFATAL("socketaddr_service : numeric conversion failed");
                return -1;
            }
        }
    }
    return 0;
}


void socketaddr_init(struct sockaddr_in *socketaddr)
{
    bzero((char *) socketaddr, sizeof(*socketaddr));
    socketaddr->sin_family = AF_INET;
}

int clientconnect(const char *host, const char *port, const char *proto)
{
    struct sockaddr_in socketaddr;
    int sockid;

    socketaddr_init(&socketaddr);
    socketaddr_service(&socketaddr, port, proto);
    socketaddr_host(&socketaddr, host);

    sockid = socket(PF_INET, prototype(proto), resolveproto(proto));
    if (sockid < 0) {
        LFATAL("clientconnect socket failed, %s", strerror(errno));
        return -1;
    }

    if (connect
        (sockid, (struct sockaddr *) &socketaddr,
         sizeof(socketaddr)) < 0) {
        LFATAL("clientconnect connect failed, %s", strerror(errno));
        return -1;
    }
    return sockid;
}

int scanaddr(const char *s, unsigned long *ip, unsigned long *mask)
{
    unsigned d1, d2, d3, d4, m;
    int res;
    if ((res =
         sscanf((char *) s, "%u.%u.%u.%u/%u", &d1, &d2, &d3, &d4, &m)) < 4)
        return 0;
    if (mask && res == 4)
        *mask = 0xFFFFFFFF;
    else if (mask)
        *mask = htonl(0xFFFFFFFF << (32 - m));
    *ip = htonl((d1 << 24) ^ (d2 << 16) ^ (d3 << 8) ^ d4);
    return res;
}

int serverinit(const char *addr, const char *port, const char *proto)
{
    struct sockaddr_in socketaddr;
    int mastersock;
    int trueval = 1;
    struct hostent *hostinfo;
    unsigned long ip;

    socketaddr_init(&socketaddr);

    if (NULL == addr) {
        socketaddr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (scanaddr(addr, &ip, NULL) != 4) {
            LFATAL("Invalid address : %s provided", addr);
            return -1;
        }
        hostinfo = gethostbyaddr((char *) &ip, 4, AF_INET);
        if (NULL == hostinfo) {
            LFATAL("gethostbyaddr : %s failed", addr);
            return -1;
        }
        socketaddr.sin_addr = *(struct in_addr *) *hostinfo->h_addr_list;
    }
    socketaddr_service(&socketaddr, port, proto);

    mastersock = socket(PF_INET, prototype(proto), resolveproto(proto));
    if (mastersock < 0) {
        LFATAL("couldn't create socket");
        return -1;
    }

    if (bind
        (mastersock, (struct sockaddr *) &socketaddr,
         sizeof(socketaddr)) < 0) {
        return -1;
    }

    setsockopt(mastersock, SOL_SOCKET, SO_REUSEADDR, &trueval,
               sizeof(trueval));

    if (prototype(proto) == SOCK_STREAM) {
        if (listen(mastersock, 5) < 0) {
            LFATAL("listen on port %d failed", socketaddr.sin_port);
            return -1;
        }
    }
    return mastersock;
}
