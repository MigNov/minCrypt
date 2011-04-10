LIBNAME=mincrypt
SOURCES=../src/mincrypt.c ../src/base64.c ../src/crc32.c

all: compile del-temp

compile:
	$(MINGW32) -o $(LIBNAME).dll -mdll $(SOURCES) -DBUILDING_DLL -Wl,--out-implib,lib$(LIBNAME).a -DWINDOWS
	$(MINGW32) -o $(LIBNAME).exe mincrypt-main.c -l$(LIBNAME) -DWINDOWS -L.

del-temp:
	rm -f *.o

clean-local: del-temp
	rm -f *.a  *.o *.dll *.exe
