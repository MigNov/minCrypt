AC_INIT([mincrypt], [0.0.4], [mignov@gmail.com])
LT_INIT([shared])
AC_ENABLE_SHARED
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror])
AM_INIT_AUTOMAKE([-Wno-portability])
#AM_MAINTAINER_MODE([enable])
AC_PROG_CXX

AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_LIB([m], [pow], [], AC_MSG_ERROR([You need libm to compile this utility]))
AC_CHECK_TOOL([MKDIR], [mkdir])
AC_CHECK_TOOL([ECHO], [echo])
AC_CHECK_TOOL([RM], [rm])
AC_CHECK_TOOL([CP], [cp])
AC_CHECK_TOOL([PHPCONFIG], [php-config])
AC_CHECK_TOOL([RPMBUILD], [rpmbuild])
AC_CHECK_TOOL([MINGW32], [i686-pc-mingw32-gcc])
AC_CHECK_TOOL([WX_CPP], [g++])
AC_CHECK_TOOL([WXCONFIG], [wx-config])

dnl Specific XML catalog file for validation of generated html
AC_ARG_WITH([xml-catalog-file],
            [AC_HELP_STRING([--with-xml-catalog-file=path],
                [path to XML catalog file for validating
                 generated html, default /etc/xml/catalog])],
            [XML_CATALOG_FILE=$withval],
            [XML_CATALOG_FILE='/etc/xml/catalog'])
AC_SUBST([XML_CATALOG_FILE])

# External programs to generate documentation
AC_PATH_PROG([XSLTPROC], [xsltproc], [no])
if test "x$XSLTPROC" = "xno"; then
    AC_MSG_ERROR([xsltproc not found])
fi

AC_PATH_PROG([XMLLINT], [xmllint], [no])
if test "x$XMLLINT" = "xno"; then
    AC_MSG_ERROR([xmllint not found])
fi

AC_PATH_PROG([XMLCATALOG], [xmlcatalog], [no])
if test "x$XMLCATALOG" = "xno"; then
    AC_MSG_ERROR([xmlcatalog not found])
fi

if test "x$WXCONFIG" = "x"; then
    WX_CPP=
    AC_SUBST([WX_CPP])
fi

dnl Specific dir for HTML output ?
AC_ARG_WITH([html-dir], [AC_HELP_STRING([--with-html-dir=path],
            [path to base html directory, default $datadir/doc/html])],
            [HTML_DIR=$withval], [HTML_DIR='$(datadir)/doc'])

AC_ARG_WITH([html-subdir], [AC_HELP_STRING([--with-html-subdir=path],
            [directory used under html-dir, default $PACKAGE-$VERSION/html])],
            [test "x$withval" != "x" && HTML_DIR="$HTML_DIR/$withval"],
            [HTML_DIR="$HTML_DIR/\$(PACKAGE)-\$(VERSION)/html"])
AC_SUBST([HTML_DIR])

AC_CONFIG_HEADERS([config.h])
#AC_CONFIG_FILES([Makefile docs/Makefile src/Makefile windows/Makefile php/Makefile tests/Makefile examples/Makefile tools/Makefile])
AC_CONFIG_FILES([Makefile src/Makefile windows/Makefile php/Makefile tests/Makefile])
AC_OUTPUT
LT_OUTPUT
