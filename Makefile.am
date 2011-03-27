ACLOCAL_AMFLAGS=-I m4
SOURCEDIR=`rpm --eval '%{_sourcedir}'`

SUBDIRS = src php tests tools docs

rpm:   dist-xz
	cp $(PACKAGE_NAME).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME).tar.xz
	rpmbuild -bb SPEC/$(PACKAGE_NAME).spec

srpm:  dist-xz
	cp $(PACKAGE_NAME).tar.xz $(SOURCEDIR)/$(PACKAGE_NAME).tar.xz
	rpmbuild -bs SPEC/$(PACKAGE_NAME).spec
