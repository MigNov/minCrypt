/*
 *  mincrypt-main.c: Minimalistic encryption system application
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#include "mincrypt.h"

#ifndef DISABLE_DEBUG
#define DEBUG_MINCRYPT_MAIN
#endif

#ifdef DEBUG_MINCRYPT_MAIN
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[mincrypt/main        ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

char *infile	= NULL;
char *outfile	= NULL;
char *password	= NULL;
char *salt	= NULL;
char *type	= NULL;
char *keyfile	= NULL;
char *dump_file = NULL;
int vector_mult	= -1;
int keysize	= 0;
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
		{"key-size", 1, 0, 'k'},
		{"key-file", 1, 0, 'f'},
		{"dump-vectors", 1, 0, 'u'},
		{0, 0, 0, 0}
	};

	char *optstring = "i:o:p:s:v:k:u:d";

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
			case 'k':
				keysize = atoi(optarg);
				if (keysize < 128)
					return 1;
				break;
			case 'f':
				keyfile = optarg;
				break;
			case 'u':
				dump_file = optarg;
				break;
			case 'v':
				vector_mult = atoi(optarg);
				if (vector_mult < 32)
					return 1;
		}
	}

	return ((((infile != NULL) && (outfile != NULL)) || ((keyfile != NULL) && (keysize > 0))) ? 0 : 1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int isPrivate = 0;

	if (parseArgs(argc, argv)) {
		printf("Syntax: %s --input-file=infile --output-file=outfile [--decrypt] [--password=pwd] [--salt=salt] "
			"[--vector-multiplier=number] [--type=base64|binary] [--simple-mode] [--key-size <keysize> "
			"--key-file <keyfile-prefix>] [--dump-vectors <dump-file>]\n",
				argv[0]);
		return 1;
	}

	if (salt == NULL)
		salt = DEFAULT_SALT_VAL;

	if (password == NULL) {
		char *tmp;

		tmp = getpass("Enter password value: ");
		if (tmp == NULL) {
			printf("Error: No password entered\n");
			return 1;
		}
		password = strdup(tmp);
		free(tmp);
	}

	if (keysize > 0) {
		int ret;
		char public_key[4096] = { 0 };
		char private_key[4096] = { 0 };

		snprintf(private_key, sizeof(private_key), "%s.key", keyfile);
		snprintf(public_key, sizeof(public_key), "%s.pub", keyfile);

		printf("Generating keys based on input data. This may take a while...\n");
		ret = mincrypt_generate_keys(keysize, salt, password, private_key, public_key);
		printf("Key generation done. Keys saved as { private = '%s', public = '%s' }\n",
			private_key, public_key);
		return ret;
	}

	if (keyfile != NULL) {
		int ret;

		if ((ret = mincrypt_read_key_file(keyfile, &isPrivate)) != 0) {
			fprintf(stderr, "Error while reading key file '%s' (error code %d, %s)\n", keyfile, ret, strerror(-ret));
			return 2;
		}

		DPRINTF("Key file %s contains %s key\n", keyfile, isPrivate ? "private" : "public");

		if (isPrivate && !decrypt) {
			fprintf(stderr, "Error: Cannot use private key for encryption\n");
			return 3;
		}

		if (!isPrivate && decrypt) {
			fprintf(stderr, "Error: Cannot use public key for decryption\n");
			return 3;
		}
	}

	if ((type != NULL) && (strcmp(type, "base64") == 0))
		if (mincrypt_set_encoding_type(ENCODING_TYPE_BASE64) != 0)
			printf("Warning: Cannot set base64 encoding, using binary encoding instead\n");

	if (simple_mode)
		if (mincrypt_set_simple_mode(1) != 0)
			printf("Warning: Cannot set simple mode for non-binary encoding\n");

	if (!decrypt)
		ret = mincrypt_encrypt_file(infile, outfile, password, salt, vector_mult);
	else
		ret = mincrypt_decrypt_file(infile, outfile, password, salt, vector_mult);

	if (dump_file != NULL)
		mincrypt_dump_vectors(dump_file);

	mincrypt_cleanup();
	
	if (ret != 0)
		fprintf(stderr, "Action failed with error code: %d\n", ret);
	else
		printf("Action has been completed successfully\n");

	return ret;
}
