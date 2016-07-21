AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-saveKeys.la
else
plugin_LTLIBRARIES = libstrongswan-saveKeys.la
endif

libstrongswan_saveKeys_la_SOURCES = saveKeys_plugin.h saveKeys_plugin.c \
	saveKeys_listener.c saveKeys_listener.h

libstrongswan_saveKeys_la_LDFLAGS = -module -avoid-version
