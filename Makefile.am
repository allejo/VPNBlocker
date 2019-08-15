lib_LTLIBRARIES = VPNBlocker.la

VPNBlocker_la_SOURCES = VPNBlocker.cpp
VPNBlocker_la_CPPFLAGS= -I$(top_srcdir)/include -I$(top_srcdir)/plugins/plugin_utils
VPNBlocker_la_LDFLAGS = -module -avoid-version -shared
VPNBlocker_la_LIBADD = $(top_builddir)/plugins/plugin_utils/libplugin_utils.la

AM_CPPFLAGS = $(CONF_CPPFLAGS)
AM_CFLAGS = $(CONF_CFLAGS)
AM_CXXFLAGS = $(CONF_CXXFLAGS)

EXTRA_DIST = \
	VPNBlocker.config.json \
	UPGRADE-2.0.md \
	LICENSE.md \
	README.md

MAINTAINERCLEANFILES =	\
	Makefile.in
