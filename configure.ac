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

AC_ARG_WITH(openvpn, AC_HELP_STRING([--with-openvpn=OPENVPN_BINARY_PATH], [specify location of openvpn binary]), [path_openvpn=${withval}])
if (test -z "${path_openvpn}"); then
    AC_PATH_PROG(OPENVPN_BINARY_PATH, [openvpn], [], $PATH:/sbin:/usr/sbin:/usr/local/sbin)
else
    OPENVPN_BINARY_PATH="${path_openvpn}"
fi

if ! test -x "$OPENVPN_BINARY_PATH"; then
    AC_MSG_ERROR([Couldn't find openvpn binary path... try 'brew install openvpn or specify correct location of openvpn'])
fi

AC_DEFINE_UNQUOTED([OPENVPN_BINARY_PATH], ["$OPENVPN_BINARY_PATH"], [Path to OpenVPN])
AC_SUBST(OPENVPN_BINARY_PATH)

AC_CONFIG_FILES([Makefile
                utils/Makefile
                etc/Makefile
                platforms/Makefile
                platforms/osx/Makefile
                platforms/epel/Makefile
                src/Makefile])

AC_OUTPUT
