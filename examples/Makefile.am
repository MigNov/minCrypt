BINARY=mincrypt-gui
OBJECTS=main.cpp utils.cpp
WXLIBS=`$(WXCONFIG) --libs`
WXFLAGS=`$(WXCONFIG) --cxxflags`
LIBS=-lmincrypt

all:
	$(WX_CPP) -o $(BINARY) $(OBJECTS) $(WXLIBS) $(WXFLAGS) $(CFLAGS) $(LIBS)

