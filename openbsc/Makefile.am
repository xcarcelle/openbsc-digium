AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

INCLUDES = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include src tests

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = openbsc.pc liblaf0rge1.pc libsccp.pc

#dist-hook:
#	rm -rf `find $(distdir) -name .svn`
