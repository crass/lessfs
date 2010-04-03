/* lib_log.h.  Generated from lib_log.h.in by configure.  */
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
 *
 *   Logging debug=0 -> Alleen fatals 
 *           debug=1 -> fatals + warnings
 *           debug=2 -> fatals + warnings + info
 *           debug=3 -> fatals + warnings + info + debug
*/

#ifdef SYSLOG
#include<syslog.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <sys/times.h>

extern char *logname;
extern char *function;
extern int debug;

#define BUFSIZE      1024

#if !defined FACILITY
#define FACILITY LOG_LOCAL0
#endif
#if !defined PRIORITY
#define PRIORITY LOG_NOTICE
#endif

#ifdef SYSLOG
#define LLINF(t,f...) {openlog(logname,LOG_PID,FACILITY);syslog(LOG_CRIT,f);closelog();}
#define LLINW(t,f...) {if ( debug > 0  ){ openlog(logname,LOG_PID,FACILITY);syslog(LOG_WARNING,f);closelog();};}
#define LLINI(t,f...) {if ( debug > 1  ){ openlog(logname,LOG_PID,FACILITY);syslog(LOG_INFO,f);closelog();};}
#define LLIND(t,f...) {if ( debug > 2  ){ openlog(logname,LOG_PID,FACILITY);syslog(LOG_DEBUG,f);closelog();};}
#else
#define LLINF(t,f...) {fprintf(stderr,"%s - %s (%i): %s: ",logname,function,getpid(),t); fprintf(stderr,f);}
#define LLINW(t,f...) {if ( debug > 0  ){ fprintf(stderr,"%s (%i): %s: \n",logname,getpid(),t); fprintf(stderr,f);};}
#define LLINI(t,f...) {if ( debug > 1 ){ fprintf(stderr,"%s (%i): %s: \n",logname,getpid(),t); fprintf(stderr,f);};}
#define LLIND(t,f...) {if ( debug > 2 ){ fprintf(stderr,"%s - %s (%i): %s: \n",logname,__PRETTY_FUNCTION__,getpid(),t); fprintf(stderr,f);};}
#endif

#define LFATAL(f...)  {LLINF("fatal",f);}
#define LINFO(f...)   {LLINI("info",f);}
#define LWARNING(f...){LLINW("warning",f);}
#ifdef DEBUG
#define LDEBUG(f...)  {LLIND("debug",f);}
#define FUNC {logname=(char *)__FILE__; function=(char *)__PRETTY_FUNCTION__;if ( debug > 4 ) tstamp();};
#define EFUNC {logname=(char *)__FILE__; function=(char *)__PRETTY_FUNCTION__;if ( debug > 4 ) estamp();};
#else
#define FUNC {};
#define EFUNC {};
#define LDEBUG(f...) {};
#endif
