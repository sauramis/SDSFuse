AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = layers_impl/align layers_impl/crypto layers_impl/loopback layers_impl/nop layers_impl/local

CXXFLAGS = -Wall -g -ldl -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse) $(CFLAGS) `libgcrypt-config --cflags` `pkg-config --cflags  glib-2.0`

bin_PROGRAMS=sfs

sfs_SOURCES = SFSFuse.c layers_conf/SFSConfig.c logging/logdef.c inih/ini.c logging/timestamps/timestamps.c  utils/utils.c utils/map/map.c  

sfs_LDADD= layers_impl/align/libalign.la layers_impl/crypto/libsfuse.la layers_impl/loopback/libloopback.la layers_impl/nop/libnop.la   layers_impl/local/liblocal.la

sfs_CFLAGS= -Wall $(CXXFLAGS)