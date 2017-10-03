AC_PREREQ(2.60)
AC_INIT([rvc], [0.9.0], [https://github.com/riboseinc/rvc/issues])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

AC_PROG_CC
AM_PROG_CC_C_O

AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_PREFIX_DEFAULT([/usr/local])

AC_SEARCH_LIBS(socket, [socket network])
AC_SEARCH_LIBS([pthread_create], [pthread])

# list all used system headers for checking
AC_CHECK_HEADERS_ONCE(m4_flatten([
    pthread.h
    string.h
    stdio.h
    string.h
    stdarg.h
    stdlib.h
    stdarg.h
    time.h
    unistd.h
    sys/stat.h
    sys/time.h
    sys/types.h
]))

AC_CHECK_FUNCS([strlcpy strlcat])

AX_CHECK_JSONC([], AC_MSG_ERROR([]))
AX_CHECK_OPENSSL([], AC_MSG_ERROR([]))

# add more host definitions if needed.
islinux=no
isdarwin=no
isfreebsd=no
isopenbsd=no

case $host_os in
  linux* )
    islinux=yes
  ;;
  darwin* )
    isdarwin=yes
  ;;
  *freebsd* )
    isfreebsd=yes
  ;;
  openbsd* )
    isopenbsd=yes
  ;;
esac

AM_CONDITIONAL([LINUX],   [test "x$islinux" = "xyes"])
AM_CONDITIONAL([DARWIN],  [test "x$isdarwin" = "xyes"])
AM_CONDITIONAL([FREEBSD], [test "x$isfreebsd" = "xyes"])
AM_CONDITIONAL([OPENBSD], [test "x$isopenbsd" = "xyes"])

# MacOS specific configuration
if test "x$isdarwin" = "xyes"; then
    CFLAGS="$CFLAGS -mmacosx-version-min=10.12 -D_DARWIN_C_SOURCE"
    LDFLAGS="$LDFLAGS -mmacosx-version-min=10.12"

    OPENVPN_BINARY_PATH=/opt/rvc/sbin/openvpn
    RVD_CONFIG_PATH=/opt/rvc/etc/rvd.json
    RVC_CONFDIR_PATH=/opt/rvc/etc/vpn.d
else
    OPENVPN_BINARY_PATH=/usr/sbin/openvpn
    RVD_CONFIG_PATH=/etc/rvc/rvd.json
    RVC_CONFDIR_PATH=/etc/rvc/vpn.d
fi

AC_DEFINE_UNQUOTED([OPENVPN_BINARY_PATH], ["$OPENVPN_BINARY_PATH"], [The path to OpenVPN binrary])
AC_SUBST(OPENVPN_BINARY_PATH)

AC_DEFINE_UNQUOTED([RVD_CONFIG_PATH], ["$RVD_CONFIG_PATH"], [The path to RVD configuration])
AC_SUBST(RVD_CONFIG_PATH)

AC_DEFINE_UNQUOTED([RVC_CONFDIR_PATH], ["$RVC_CONFDIR_PATH"], [The directory path to RVC configuration])
AC_SUBST(RVC_CONFDIR_PATH)

AC_ARG_ENABLE(debug,
     AS_HELP_STRING(--enable-debug, turn on debugging (disabled by default)),
     [], [enable_debug=no]
)
if test "x$enable_debug" = "xyes" ; then
    CFLAGS="$CFLAGS -g3 -O0 -DDEBUG"
fi

AC_ARG_ENABLE(profiling,
     AS_HELP_STRING(--enable-profiling, turn on profiling (disabled by default)),
     [], [enable_profiling=no]
)
if test "x$enable_profiling" = "xyes" ; then
    CFLAGS="$CFLAGS -pg"
fi

AC_CONFIG_FILES([Makefile
                utils/Makefile
                etc/rvd.json
                etc/Makefile
                platforms/Makefile
                platforms/osx/Makefile
                platforms/epel/Makefile
                src/Makefile
                ])

AC_OUTPUT
