SUBDIRS = netlink nl80211

lib_LTLIBRARIES = libwcap.la

# Where to install the headers on the system
libwcap_ladir = $(includedir)/zutils

# Headers to install
libwcap_la_HEADERS =

# Sources to include in the package
libwcap_la_SOURCES = \
    $(libwcap_la_HEADERS)

libwcap_la_LIBADD = \
	netlink/libnetlink.la \
	nl80211/libnl80211.la
	