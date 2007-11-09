AM_CFLAGS = @CFLAGS@
SUBDIRS = .

CFLAGS = \
       $(OPENWSMAN_CFLAGS)


libwseventlistener_la_SOURCES = \
	shttpd.c \
	eventlistener.c

libwseventlistener_la_LIBADD = $(OPENWSMAN_LIBS) -lpthread

lib_LTLIBRARIES = libwseventlistener.la
