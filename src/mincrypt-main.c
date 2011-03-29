/*
 *  mincrypt-main.c: Minimalistic encryption system application
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

//#define DEBUG_MINCRYPT

#include "mincrypt.h"

#ifdef DEBUG_MINCRYPT
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "mincrypt-main: " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

char *infile	= NULL;
char *outfile	= NULL;
char *password	= NULL;
char *salt	= NULL;
char *type	= NULL;
int vector_mult	= -1;
int decrypt	= 0;
int simple_mode	= 0;

int parseArgs(int argc, char * const argv[]) {
	int option_index = 0, c;
	struct option long_options[] = {
		{"input-file", 1, 0, 'i'},
		{"output-file", 1, 0, 'o'},
		{"password", 1, 0, 'p'},
		{"salt", 1, 0, 's'},
		{"decrypt", 0, 0, 'd'},
		{"type", 1, 0, 't'},
		{"simple-mode", 0, 0, 'm'},
		{"vector-multiplier", 1, 0, 'v'},
		{0, 0, 0, 0}
	};

	char *optstring = "i:o:p:s:v:d";

	while (1) {
		c = getopt_long(argc, argv, optstring,
			long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'i':
				infile = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			case 's':
				salt = optarg;
				break;
			case 't':
				type = optarg;
				break;
			case 'm':
				simple_mode = 1;
				break;
			case 'd':
				decrypt = 1;
				break;
			case 'v':
				vector_mult = atoi(optarg);
				if (vector_mult < 32)
					return 1;
		}
	}

	return (((infile != NULL) && (outfile != NULL)) ? 0 : 1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	
	if (parseArgs(argc, argv)) {
		printf("Syntax: %s --input-file=infile --output-file=outfile [--decrypt] [--password=pwd] [--salt=salt] "
			"[--vector-multiplier=number] [--type=base64|binary] [--simple-mode]\n",
				argv[0]);
		return 1;
	}
	
	if ((salt == NULL) || (password == NULL)) {
		char *tmp;

		tmp = getpass("Enter salt value: ");
		if (tmp == NULL) {
			printf("Error: No salt entered\n");
			return 1;
		}
		salt = strdup(tmp);

		tmp = getpass("Enter pasword: ");
		if (tmp == NULL) {
			printf("Error: No password entered\n");
			return 1;
		}
		password = strdup(tmp);
	}

	if ((type != NULL) && (strcmp(type, "base64") == 0))
		if (crypt_set_output_type(OUTPUT_TYPE_BASE64) != 0)
			printf("Warning: Cannot set base64 encoding, using binary encoding instead\n");

	if (simple_mode)
		if (crypt_set_simple_mode(1) != 0)
			printf("Warning: Cannot set simple mode for non-binary encoding\n");

	if (!decrypt)
		ret = crypt_encrypt_file(infile, outfile, password, salt, vector_mult);
	else
		ret = crypt_decrypt_file(infile, outfile, password, salt, vector_mult);
	    
	crypt_cleanup();
	
	if (ret != 0)
		fprintf(stderr, "Action failed with error code: %d\n", ret);
	else
		printf("Action has been completed successfully\n");

	return ret;
}
