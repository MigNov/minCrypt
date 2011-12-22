# Library form
lib_LTLIBRARIES = libmincrypt.la
libmincrypt_la_CFLAGS = -Wall -fPIC
libmincrypt_la_SOURCES = mincrypt.c crc32.c base64.c byteops.c asymmetric.c mincrypt.h
libmincrypt_la_LIBS = -lm

# Standalone binary form
bin_PROGRAMS = mincrypt
mincrypt_CFLAGS = -Wall -fPIC
mincrypt_SOURCES = mincrypt-main.c
mincrypt_LDADD = libmincrypt.la

all:
	$(CC) -Wall -fPIC -DHAVE_CONFIG_H -shared -DCOMPILE_DL_MINCRYPT=1 $(libmincrypt_la_LIBS) -o libmincrypt.so $(libmincrypt_la_SOURCES)
	cp -af libmincrypt.so ../examples

install-exec-local:
	cp -af libmincrypt.so $(DESTDIR)$(libdir)/libmincrypt.so

uninstall-local:
	rm -f $(DESTDIR)$(libdir)/libmincrypt.so
