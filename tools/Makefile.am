ECHO=echo
BIN=`pwd`/bin

all: make-bin make-api-docs-gen make-graph make-relevance generate-docs

EXTRA_DIST = relevance/relevance.c graph/graph.c api-docs/generate-api-docs.c \
             relevance/Makefile graph/Makefile api-docs/Makefile

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

make-api-docs-gen:
	@$(ECHO) "Compiling API docs tool"
	@cd api-docs; $(MAKE) $(MFLAGS)
	@mv api-docs/generate-api-docs $(BIN)
	@$(ECHO) "API docs tool copied to bin"

generate-docs:
	@$(BIN)/generate-api-docs --clib ../src/mincrypt.c ../docs/api-reference.html.in
	@$(BIN)/generate-api-docs --private --clib ../src/mincrypt.c ../docs/dev-api-reference.html.in
	@$(BIN)/generate-api-docs ../php/mincrypt-php.c ../docs/php-api-reference.html.in
	@$(BIN)/generate-api-docs --private ../php/mincrypt-php.c ../docs/dev-papi-reference.html.in
