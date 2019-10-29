dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.69)
AC_INIT(wcap, 1.0, <kevin.mahoney@zenotec.net>)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL

LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS
AC_CHECK_HEADER_STDBOOL

PKG_CHECK_MODULES([LIBNL3], [libnl-3.0], [], [AC_MSG_ERROR([Unable to find libnl-3])])
PKG_CHECK_MODULES([NLGENL3], [libnl-genl-3.0], [], [AC_MSG_ERROR([Unable to find libnl-genl-3])])
PKG_CHECK_MODULES([NLRTNL3], [libnl-route-3.0], [], [AC_MSG_ERROR([Unable to find libnl-route-3])])

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	lib/netlink/Makefile
	lib/nl80211/Makefile
	src/Makefile
])
AC_OUTPUT

