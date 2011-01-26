ECHO=echo
BIN=`pwd`/bin

all: make-bin make-graph make-relevance

make-bin:
	mkdir -p $(BIN)

make-graph:
	@$(ECHO) "Compiling graph tool"
	@cd graph; $(MAKE) $(MFLAGS)
	@mv graph/graph $(BIN)
	@$(ECHO) "Graph tool copied to bin"

make-relevance:
	@$(ECHO) "Compiling relevance tool"
	@cd relevance; $(MAKE) $(MFLAGS)
	@mv relevance/relevance $(BIN)
	@$(ECHO) "Relevance tool copied to bin"
