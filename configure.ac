AC_INIT(wdfs, 1.0, [noedler@web.de])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)

AC_CHECK_HEADERS([pthread.h])

AC_PROG_CC
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(WDFS, [fuse >= 2.3.0  neon >= 0.24.7  glib-2.0])

CFLAGS="$CFLAGS -Wall -D_GNU_SOURCE -D_REENTRANT $WDFS_CFLAGS"
LIBS="$WDFS_LIBS"

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

# eof
