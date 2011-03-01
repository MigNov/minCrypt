NAME=mincrypt-php
CC=cc
CP=cp
RM=rm
ECHO=echo
LIBDEFS=-DNO_MAIN
PHPINC=`php-config --includes`
PHPEDIR=`php-config --extension-dir`
PHPCDIR=`php-config --configure-options | sed -n 's|.*--with-config-file-scan-dir=\([^ ]*\).*|\1|p'`
MINCRYPT_OBJECTS=../src/mincrypt.o ../src/crc32.o ../src/base64.o

EXTRA_DIST = mincrypt-php.c php_mincrypt.h

all: build clean-temp

build:
	$(CC) -Wall -fpic -DCOMPILE_DL_MINCRYPT=1 $(PHPINC) -c -o $(NAME).o mincrypt-php.c
	$(CC) -Wall -shared $(LIBS) -rdynamic -o $(NAME).so $(NAME).o $(MINCRYPT_OBJECTS) $(LIBDEFS)
	$(ECHO) "Extension compiled as $(NAME).so"

install-exec-local:
	mkdir -p $(DESTDIR)$(PHPEDIR)
	$(CP) $(NAME).so $(DESTDIR)$(PHPEDIR)
	mkdir -p $(DESTDIR)$(PHPCDIR)
	$(ECHO) "extension=$(NAME).so" > $(DESTDIR)$(PHPCDIR)/$(NAME).ini


uninstall-local:
	$(RM) -f $(DESTDIR)$(PHPCDIR)/$(NAME).ini
	$(RM) -f $(DESTDIR)$(PHPEDIR)/$(NAME).so

clean-temp:
	$(RM) -f *.o
