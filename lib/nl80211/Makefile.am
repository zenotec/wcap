noinst_LTLIBRARIES = libnl80211.la

AM_CPPFLAGS = \
	-I$(srcdir)/../netlink

AM_LDFLAGS =

libnl80211_la_CPPFLAGS = \
	${AM_CPPFLAGS} \
	${LIBNL3_CFLAGS} \
	${NLGENL3_CFLAGS} \
	${NLRTNL3_CFLAGS}

libnl80211_la_LDFLAGS = \
	${AM_LDFLAGS} \
	${LIBNL3_LIBS} \
	${NLGENL3_LIBS} \
	${NLRTNL3_LIBS}

libnl80211_la_SOURCES = \
    nl80211.c \
    nl80211_phy.c \
    nl80211_iface.c 
    