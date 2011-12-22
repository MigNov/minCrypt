ACLOCAL_AMFLAGS=-I m4
SOURCEDIR=`rpm --eval '%{_sourcedir}'`

#SUBDIRS = src php tests windows docs examples tools
SUBDIRS = src php tests windows

EXTRA_DIST = LICENSE html

test:
	cd tests && ./runtests.sh

rpm:   dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	$(RPMBUILD) -bb $(PACKAGE_NAME).spec

srpm:  dist-xz
	$(CP) $(PACKAGE_NAME)-$(VERSION).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME)-$(VERSION).tar.xz
	$(RPMBUILD) -bs $(PACKAGE_NAME).spec
