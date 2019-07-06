#
# $Id$
#

noinst_LIBRARIES = libgateway.a

bin_PROGRAMS = wihome \
	whstop
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
wihome_LDADD = libgateway.a $(top_builddir)/libhttpd/libhttpd.la

wihome_SOURCES = gatewaymain.c

libgateway_a_SOURCES = arphandler.c \
	debug.c \
	dhcphandler.c \
	dnshandler.c \
	functions.c \
	gatewayapi.c \
	homeauth.c \
	homeconfig.c \
	homenet.c \
	httphandler.c \
	ipprocessing.c

noinst_HEADERS = common.h \
	arphandler.h \
	debug.h \
	dhcphandler.h \
	dnshandler.h \
	functions.h \
	gatewayapi.h \
	homeauth.h \
	homeconfig.h \
	homenet.h \
	httphandler.h \
	ipprocessing.h


whstop_LDADD = libgateway.a

whstop_SOURCES = whomestop.c
