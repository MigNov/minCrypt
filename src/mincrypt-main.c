/*
 *  mincrypt-main.c: Minimalistic encryption system application
 *
 *  Copyright (c) 2006-2007, Michal Novotny <minovotn@redhat.com>
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

int main(int argc, char *argv[])
{
	char *infile, *outfile, *tmp;
	char salt[1024] = { 0 }, password[1024] = { 0 };
	int decrypt = 0, nextIdx = 1, ret = 0, vector_multiplier = -1;//0x40;
	
	if (argc < 3) {
		printf("Syntax: %s [-d] input_file output_file\n", argv[0]);
		return 1;
	}
	
	if (strcmp(argv[1], "-d") == 0) {
		nextIdx++;
		decrypt = 1;
	}
	
	infile = strdup(argv[nextIdx++]);
	if ((argv[nextIdx] == NULL) || (strlen(argv[nextIdx]) == 0)) {
		printf("Error: Output file name is missing\n");
		return 1;
	}
	outfile = strdup(argv[nextIdx]);
	
	tmp = getpass("Enter salt value: ");
	if ((tmp != NULL) && (strlen(tmp) > 0))
		strncpy(salt, tmp, sizeof(salt));
	else
		strncpy(salt, DEFAULT_SALT_VAL, sizeof(salt));
	
	tmp = getpass("Enter pasword: ");
	if ((tmp != NULL) && (strlen(tmp) > 0))
		strncpy(password, tmp, sizeof(password));
	else {
		printf("Error: No password entered\n");
		return 1;
	}

	//crypt_set_output_type(OUTPUT_TYPE_BASE64);
	if (!decrypt)
	    ret = crypt_encrypt_file(infile, outfile, password, salt, vector_multiplier);
	else
	    ret = crypt_decrypt_file(infile, outfile, password, salt, vector_multiplier);
	    
	crypt_cleanup();
	
	return ret;
}
