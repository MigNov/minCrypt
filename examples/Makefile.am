BINARY=mincrypt-gui
OBJECTS=main.cpp utils.cpp
WXLIBS=`$(WXCONFIG) --libs`
WXFLAGS=`$(WXCONFIG) --cxxflags`
LIBS=-lmincrypt

EXTRA_DIST = main.cpp utils.cpp mincrypt.h interface.h

all:
	$(WX_CPP) -o $(BINARY) $(OBJECTS) $(WXLIBS) $(WXFLAGS) $(CFLAGS) $(LIBS)

