BINARY=graph
SOURCES=graph.c
LIBS=-lgd

all: clean graph

clean:
	rm -f $(BINARY)
graph:
	$(CC) -Wall -Werror -o $(BINARY) $(SOURCES) $(LIBS)
