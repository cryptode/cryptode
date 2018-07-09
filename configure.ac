AC_PREREQ(2.60)
AC_INIT([rvc], [1.2.1], [https://github.com/riboseinc/rvc/issues])
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

AC_CHECK_FUNCS([strlcpy strlcat getprogname])

AX_CHECK_JSONC([], AC_MSG_ERROR([]))
AX_CHECK_OPENSSL([], AC_MSG_ERROR([]))
AX_CHECK_NEREON([], AC_MSG_ERROR([]))

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

    OPENVPN_BINARY_PATH=/opt/openvpn/sbin/openvpn
    RVD_CONFIG_PATH=/opt/rvc/etc/rvd.conf
    RVC_CONFDIR_PATH=/opt/rvc/etc/vpn.d

    RVD_LDADD="$JSONC_LIBDIR/libjson-c.a $NEREON_LIBDIR/libnereon.a"
    RVC_LDADD="$JSONC_LIBDIR/libjson-c.a $OPENSSL_LIBDIR/libcrypto.a $NEREON_LIBDIR/libnereon.a"

    RVC_USER_ID=501
else
    OPENVPN_BINARY_PATH=/usr/sbin/openvpn
    RVD_CONFIG_PATH=/etc/rvc/rvd.conf
    RVC_CONFDIR_PATH=/etc/rvc/vpn.d

    RVD_LDADD="$JSONC_LIBS $NEREON_LIBS"
    RVC_LDADD="$JSONC_LIBS $OPENSSL_LIBS $NEREON_LIBS"

    RVC_USER_ID=-1
fi

AC_DEFINE_UNQUOTED([RVC_USER_ID], ["$RVC_USER_ID"], [The User ID for RVC])
AC_SUBST(RVC_USER_ID)

AC_DEFINE_UNQUOTED([OPENVPN_BINARY_PATH], ["$OPENVPN_BINARY_PATH"], [The path to OpenVPN binary])
AC_SUBST(OPENVPN_BINARY_PATH)

AC_DEFINE_UNQUOTED([RVD_CONFIG_PATH], ["$RVD_CONFIG_PATH"], [The path to RVD configuration])
AC_SUBST(RVD_CONFIG_PATH)

AC_DEFINE_UNQUOTED([RVC_CONFDIR_PATH], ["$RVC_CONFDIR_PATH"], [The directory path to RVC configuration])
AC_SUBST(RVC_CONFDIR_PATH)

AC_SUBST(RVD_LDADD)
AC_SUBST(RVC_LDADD)

AC_ARG_ENABLE(
  [strict-path],
  [AS_HELP_STRING([--enable-strict-path], [enable strict for the paths of rvd and rvc processes @<:@default=yes@:>@])],
  ,
  [enable_strict_path="yes"]
)
if test "x$enable_strict_path" = "xyes" ; then
    CFLAGS="$CFLAGS -g3 -O0 -DENABLE_STRICT_PATH"
fi

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

TESTS_CFLAGS=""
AC_MSG_CHECKING(whether to run tests)
AC_ARG_ENABLE([tests],
   [AS_HELP_STRING([--enable-tests], [enable running tests on make check (default is NO)])],
   [enable_tests=${enableval}],
   [enable_tests=no])
AC_MSG_RESULT($enable_test)
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = "xyes"])
if test "x$enable_tests" = "xyes" ; then
AC_MSG_NOTICE([yes])
TESTS_CFLAGS="$TESTS_CFLAGS -fno-builtin"
else
AC_MSG_NOTICE([no])
fi
AC_SUBST([TESTS_CFLAGS])

AC_CONFIG_FILES([Makefile
                etc/Makefile
                platforms/Makefile
                platforms/macos/Makefile
                platforms/epel/Makefile
                src/Makefile
                src/rvd.nos
                upload_release.sh
                etc/rvd.conf
                platforms/epel/rvc.spec
                tests/Makefile
                ])

AC_OUTPUT
