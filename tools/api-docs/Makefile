BINARY=generate-api-docs
SOURCES=generate-api-docs.c
LIBS=

all: clean compile

clean:
	rm -f $(BINARY)
compile:
	$(CC) -Wall -Werror -o $(BINARY) $(SOURCES) $(LIBS)
