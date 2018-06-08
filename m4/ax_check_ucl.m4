# SYNOPSIS
#
#   AX_CHECK_LIBUCL([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for libucl in a number of default spots, or in a user-selected
#   spot (via --with-libucl).  Sets
#
#     LIBUCL_INCLUDES to the include directives required
#     LIBUCL_LIBS to the -l directives required
#     LIBUCL_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets LIBUCL_INCLUDES such that source files should include
#   ucl.h like so:
#
#     #include <ucl.h>

AU_ALIAS([CHECK_LIBUCL], [AX_CHECK_LIBUCL])
AC_DEFUN([AX_CHECK_LIBUCL], [
    found=false
    AC_ARG_WITH([libucl],
        [AS_HELP_STRING([--with-libucl=DIR],
            [root of the libucl directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-libucl value])
              ;;
            *) libucldirs="$withval"
              ;;
            esac
        ], [
            libucldirs="/usr/local/ucl /usr/lib/ucl /usr/ucl /usr/pkg /usr/local /usr"
        ]
        )

    LIBUCL_INCLUDES=
    for libucldir in $libucldirs; do
        AC_MSG_CHECKING([for ucl.h in $libucldir])
        if test -f "$libucldir/include/ucl.h"; then
            LIBUCL_INCLUDES="-I$libucldir/include/"
            LIBUCL_LDFLAGS="-L$libucldir/lib"
            LIBUCL_LIBS="-lucl"
            LIBUCL_LIBDIR="$libucldir/lib"
            found=true
            AC_MSG_RESULT([yes])
            break
        else
            AC_MSG_RESULT([no])
        fi
    done

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against libucl works])
    echo "Trying link with LIBUCL_LDFLAGS=$LIBUCL_LDFLAGS;" \
        "LIBUCL_LIBS=$LIBUCL_LIBS; LIBUCL_INCLUDES=$LIBUCL_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $LIBUCL_LDFLAGS"
    LIBS="$LIBUCL_LIBS $LIBS"
    CPPFLAGS="$LIBUCL_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <ucl.h>], [ucl_parser_new(0)])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([LIBUCL_INCLUDES])
    AC_SUBST([LIBUCL_LIBS])
    AC_SUBST([LIBUCL_LDFLAGS])
    AC_SUBST([LIBUCL_LIBDIR])
])
