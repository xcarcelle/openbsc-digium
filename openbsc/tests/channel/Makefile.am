INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3

noinst_PROGRAMS = channel_test

channel_test_SOURCES = channel_test.c \
	$(top_srcdir)/src/db.c \
	$(top_srcdir)/src/gsm_subscriber_base.c \
	$(top_srcdir)/src/gsm_subscriber.c \
	$(top_srcdir)/src/debug.c \
	$(top_srcdir)/src/timer.c \
	$(top_srcdir)/src/select.c \
	$(top_srcdir)/src/talloc.c \
	$(top_srcdir)/src/gsm_data.c \
	$(top_srcdir)/src/signal.c \
	$(top_srcdir)/src/statistics.c \
	$(top_srcdir)/src/bts_ipaccess_nanobts.c \
	$(top_srcdir)/src/bts_siemens_bs11.c \
	$(top_srcdir)/src/tlv_parser.c
channel_test_LDADD = -ldl -ldbi

