noinst_LTLIBRARIES = libnetlink.la

AM_CPPFLAGS = 

AM_LDFLAGS = 

libnetlink_la_CPPFLAGS = \
	${AM_CPPFLAGS} \
	${LIBNL3_CFLAGS} \
	${NLGENL3_CFLAGS} \
	${NLRTNL3_CFLAGS}

libnetlink_la_LDFLAGS = \
	${AM_LDFLAGS} \
	${LIBNL3_LIBS} \
	${NLGENL3_LIBS} \
	${NLRTNL3_LIBS}

libnetlink_la_SOURCES = \
    netlink.c \
	route.c \
	iface.c
