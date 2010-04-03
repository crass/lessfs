#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.01)
AC_INIT(lessfs, 1.0.8, bugs@lessfs.com)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([listdb.c])
AC_CONFIG_HEADER([config.h])

AC_SUBST(DEPS_CFLAGS)
# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_FUNC_ALLOCA
AC_HEADER_DIRENT
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AM_PROG_CC_C_O
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRCOLL
AC_CHECK_FUNCS([getpass uname strcasecmp bzero gethostbyaddr gethostbyname gettimeofday memmove memset mkdir select setenv socket strchr strdup strerror strrchr strstr])

AC_CHECK_HEADERS([sys/vfs.h arpa/inet.h fcntl.h inttypes.h limits.h malloc.h memory.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h utime.h])

# Check whether to enable filesystem encryption
CRYPTO_MSG="no"
AC_ARG_WITH(crypto,
        [  --with-crypto           Enable lessfs filesystem encryption.],
        [
                if test "x$withval" != "xno" ; then
                        AC_DEFINE(ENABLE_CRYPTO, 1,
                                [Define if you want to allow filesystem encryption])
			CRYPTO_LIBS="$LIBS -lssl"
                        CRYPTO_MSG="yes"
			AC_CHECK_HEADERS(openssl/ssl.h, [], [], [
			])
			MYDEPS="$MYDEPS openssl > 0.9.5"
                fi
        ]
)

LZO_MSG="no"
AC_ARG_WITH(lzo,
        [  --with-lzo              Enable the use of LZO compression instead of QUICKLZ.],
        [
                if test "x$withval" != "xno" ; then
                        AC_DEFINE(LZO, 1,
                                [Define if you want LZO compression])
			LZO_LIBS="$LIBS -llzo2"
                        EXTRAFILES=lib_lzo.c
			AC_CHECK_HEADERS(lzo/lzoconf.h, [], [], [
			])
			AC_CHECK_LIB(lzo2, lzo1a_compress, [LZO_LIBS="-llzo2"], [AC_MSG_ERROR("No liblzo2 found")])
                        LZO_MSG="yes"
                fi
        ]
)

DEBUG_MSG="no"
AC_ARG_ENABLE(debug,
        [  --enable-debug          Enable debug messages],
        [
                if test "x$withval" != "xno" ; then
                        AC_DEFINE(DEBUG, 1,
                                [Define if you want debug information])
                        DEBUG_MSG="yes"
                fi
        ]
)

SHA3_MSG="no"
AC_ARG_WITH(sha3,
        [  --with-sha3             Enable the use of Blue Midnight Wish instead of tiger hashes.],
        [
                if test "x$withval" != "xno" ; then
                        AC_DEFINE(SHA3, 1,
                                [Define if you want Blue Midnight Wish hashes])
                        EXTRAFILES=lib_BMW.c
                        SHA3_MSG="yes"
                fi
        ]
)

AC_SUBST(CRYPTO_FLAGS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(LZO_LIBS)
PKG_CHECK_MODULES(DEPS, tokyocabinet >= 1.4.21 fuse >= 2.8.0 ${MYDEPS})
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
