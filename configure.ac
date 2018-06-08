AC_INIT([nftables], [0.9.0], [netfilter-devel@vger.kernel.org])
AC_DEFINE([RELEASE_NAME], ["Fearless Fosdick"], [Release name])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADER([config.h])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--disable-debug], [Disable debugging symbols]),
	      AS_IF([test "x$enable_debug" = "xno"], [with_debug=no], [with_debug=yes]),
	      [with_debug=yes])
AC_SUBST(with_debug)
AM_CONDITIONAL([BUILD_DEBUG], [test "x$with_debug" != xno])

AC_ARG_ENABLE([man-doc],
	      AS_HELP_STRING([--disable-man-doc], [Disable man page documentation]),
	      AS_IF([test "x$enable_man_doc" = "xno"], [enable_man_doc=no],
	      [enable_man_doc=yes]), [enable_man_doc=yes])
AM_CONDITIONAL([BUILD_MAN], [test "x$enable_man_doc" == "xyes" ])

AC_ARG_ENABLE([pdf-doc],
	      AS_HELP_STRING([--enable-pdf-doc], [Enable PDF documentation]),
	      AS_IF([test "x$enable_pdf_doc" = "xno"], [enable_pdf_doc=no],
	      [enable_pdf_doc=yes]), [enable_pdf_doc=no])
AM_CONDITIONAL([BUILD_PDF], [test "x$enable_pdf_doc" == "xyes" ])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_SED
AM_PROG_LEX
AC_PROG_YACC

if test -z "$ac_cv_prog_YACC"
then
        echo "*** Error: No suitable bison/yacc found. ***"
        echo "    Please install the 'bison' package."
        exit 1
fi
if test -z "$ac_cv_prog_LEX"
then
        echo "*** Error: No suitable flex/lex found. ***"
        echo "    Please install the 'flex' package."
        exit 1
fi

AM_PROG_AR
AM_PROG_LIBTOOL

AM_COND_IF([BUILD_MAN], [
	AC_CHECK_PROG(DOCBOOK2X_MAN, [docbook2x-man], [docbook2x-man], [no])
	AC_CHECK_PROG(DOCBOOK2MAN, [docbook2man], [docbook2man], [no])
	AC_CHECK_PROG(DB2X_DOCBOOK2MAN, [db2x_docbook2man], [db2x_docbook2man], [no])
	AS_IF([test "$DOCBOOK2X_MAN" != "no"], [DB2MAN="$DOCBOOK2X_MAN"],
	      [AS_IF([test "$DOCBOOK2MAN" != "no"], [DB2MAN="$DOCBOOK2MAN"],
		     [AS_IF([test "$DB2X_DOCBOOK2MAN" != "no"],
			    [DB2MAN="$DB2X_DOCBOOK2MAN"],
			    [AC_MSG_ERROR([docbook2x-man/db2x_docbook2man not found, required for building man pages])]
		     )]
	     )]
	)
	AC_SUBST(DB2MAN)

	[need_a2x=yes]
])

AM_COND_IF([BUILD_PDF], [
	AC_CHECK_PROG(DBLATEX, [dblatex], [found], [no])
	AS_IF([test "$DBLATEX" == "no"],
	      [AC_MSG_ERROR([dblatex not found])])

	[need_a2x=yes]
])

AS_IF([test "$need_a2x" = "yes"], [
       AC_CHECK_PROG(A2X, [a2x], [found], [no])
       AS_IF([test "$A2X" != "found"],
	     [AC_MSG_ERROR([a2x not found])])
])

PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.1.1])

AC_ARG_WITH([mini-gmp], [AS_HELP_STRING([--with-mini-gmp],
            [Use builtin mini-gmp (for embedded builds)])], [],
            [with_mini_gmp=no])
AS_IF([test "x$with_mini_gmp" != xyes], [
AC_CHECK_LIB([gmp],[__gmpz_init], , AC_MSG_ERROR([No suitable version of libgmp found]))
])
AM_CONDITIONAL([BUILD_MINIGMP], [test "x$with_mini_gmp" == xyes])

AC_ARG_WITH([cli], [AS_HELP_STRING([--without-cli],
            [disable interactive CLI (libreadline support)])],
            [], [with_cli=yes])
AS_IF([test "x$with_cli" != xno], [
AC_CHECK_LIB([readline], [readline], ,
	     AC_MSG_ERROR([No suitable version of libreadline found]))
AC_DEFINE([HAVE_LIBREADLINE], [1], [])
])
AC_SUBST(with_cli)
AM_CONDITIONAL([BUILD_CLI], [test "x$with_cli" != xno])

AC_ARG_WITH([xtables], [AS_HELP_STRING([--with-xtables],
            [Use libxtables for iptables interaction)])],
	    [with_libxtables=$withval], [with_libxtables=no])
AS_IF([test "x$with_libxtables" != xno], [
PKG_CHECK_MODULES([XTABLES], [xtables >= 1.6.1])
AC_DEFINE([HAVE_LIBXTABLES], [1], [0])
])
AC_SUBST(with_libxtables)
AM_CONDITIONAL([BUILD_XTABLES], [test "x$with_libxtables" == xyes])

AC_ARG_WITH([json], [AS_HELP_STRING([--with-json],
            [Enable JSON output support)])],
	    [], [with_json=no])
AS_IF([test "x$with_json" != xno], [
AC_CHECK_LIB([jansson], [json_object], ,
	AC_MSG_ERROR([No suitable version of libjansson found]))
AC_DEFINE([HAVE_LIBJANSSON], [1], [Define if you have libjansson])
])
AC_SUBST(with_json)
AM_CONDITIONAL([BUILD_JSON], [test "x$with_json" != xno])

AC_CONFIG_FILES([					\
		Makefile				\
		libnftables.pc				\
		src/Makefile				\
		include/Makefile			\
		include/nftables/Makefile		\
		include/linux/Makefile			\
		include/linux/netfilter/Makefile	\
		include/linux/netfilter_arp/Makefile	\
		include/linux/netfilter_bridge/Makefile	\
		include/linux/netfilter_ipv4/Makefile	\
		include/linux/netfilter_ipv6/Makefile	\
		files/Makefile				\
		files/nftables/Makefile			\
		doc/Makefile				\
		])
AC_OUTPUT

echo "
nft configuration:
  cli support:			${with_cli}
  enable debugging symbols:	${with_debug}
  use mini-gmp:			${with_mini_gmp}
  enable man page:              ${enable_man_doc}
  enable pdf documentation:	${enable_pdf_doc}
  libxtables support:		${with_libxtables}
  json output support:          ${with_json}"
