bin_PROGRAMS=wcap

AM_CPPFLAGS = \
	-I$(srcdir)/../lib/netlink \
	-I$(srcdir)/../lib/nl80211

AM_LDFLAGS =

wcap_CPPFLAGS = \
	${AM_CPPFLAGS} \
	${LIBNL3_CFLAGS} \
	${NLGENL3_CFLAGS} \
	${NLRTNL3_CFLAGS}

wcap_LDFLAGS = \
	${AM_LDFLAGS} \
	${LIBNL3_LIBS} \
	${NLGENL3_LIBS} \
	${NLRTNL3_LIBS}

wcap_SOURCES = \
	server.c \
	client.c \
	wcap.c

wcap_LDADD = \
	${top_builddir}/lib/libwcap.la
