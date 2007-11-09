AM_CFLAGS = @CFLAGS@

CFLAGS = \
       $(OPENWSMAN_CFLAGS)

INCLUDES = -I$(top_srcdir)/lib
       
LIBS = \
       $(top_builddir)/lib/libwseventlistener.la

wseventsink_SOURCES = eventsink.c

bin_PROGRAMS = \
	wseventsink
