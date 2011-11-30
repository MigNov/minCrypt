NAME=mincrypt-php
CC=gcc
PHPINC=`$(PHPCONFIG) --includes`
PHPEDIR=`$(PHPCONFIG) --extension-dir`
PHPCDIR=`$(PHPCONFIG) --configure-options | sed -n 's|.*--with-config-file-scan-dir=\([^ ]*\).*|\1|p'`
MINCRYPT_OBJECTS=../src/libmincrypt_la-mincrypt.o ../src/libmincrypt_la-crc32.o ../src/libmincrypt_la-base64.o ../src/libmincrypt_la-byteops.o ../src/libmincrypt_la-asymmetric.o

EXTRA_DIST = mincrypt-php.c mincrypt-php.h

all: build clean-temp

build:
	$(CC) -Wall -fPIC -DCOMPILE_DL_MINCRYPT=1 $(PHPINC) -c -o $(NAME).o mincrypt-php.c
	$(CC) -Wall -fPIC -shared $(LIBS) -rdynamic -o $(NAME).so $(NAME).o $(MINCRYPT_OBJECTS)
	$(ECHO) "Extension compiled as $(NAME).so"

install-exec-local:
	mkdir -p $(DESTDIR)$(PHPEDIR)
	$(CP) $(NAME).so $(DESTDIR)$(PHPEDIR)
	mkdir -p $(DESTDIR)$(PHPCDIR)
	$(RM) -f $(DESTDIR)$(PHPCDIR)/$(NAME).ini
	echo "extension=$(NAME).so" > $(DESTDIR)$(PHPCDIR)/$(NAME).ini


uninstall-local:
	$(RM) -f $(DESTDIR)$(PHPCDIR)/$(NAME).ini
	$(RM) -f $(DESTDIR)$(PHPEDIR)/$(NAME).so

clean-temp:
	$(RM) -f *.o
