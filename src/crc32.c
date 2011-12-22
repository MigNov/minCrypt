/*
 *  crc32.c: 32-bit cyclic-redundancy-check (CRC-32) calculation implementation
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#include "mincrypt.h"

//#define TEST_CRC

#ifndef DISABLE_DEBUG
#define DEBUG_CRC
#endif

#ifdef DEBUG_CRC
#define DPRINTF(fmt, args...) \
do { fprintf(stderr, "[mincrypt/crc32       ] " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

uint32_t crc_tab[256];
int crc_haveTab = 0;

void crc32_gentab()
{
	unsigned long crc, poly;
	int i, j;

	DPRINTF("Generating table\n");

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 8; j > 0; j--)
		{
		if (crc & 1)
			crc = (crc >> 1) ^ poly;
		else
			crc >>= 1;
		}
		crc_tab[i] = crc;
	}

	crc_haveTab = 1;
}

uint32_t crc32_block(unsigned char *block, uint32_t length, uint64_t initVal)
{
	register unsigned long crc;
	unsigned long i;

	DPRINTF("Calculating CRC for 0x%" PRIx32 " bytes, init CRC value is 0x%" PRIx64 "\n", length, initVal);

	if (!crc_haveTab)
		crc32_gentab();

	crc = initVal;
	for (i = 0; i < length; i++)
		crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];

	return crc;
}

uint32_t crc32_file(char *filename, int chunkSize)
{
	int fd;
	long size;
	unsigned char *data = NULL;
	uint32_t ret = 0;
	int rc;

	fd = open(filename, O_RDONLY);
        if (chunkSize < 0) {
		size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		DPRINTF("Got %s size: 0x%lx bytes\n", filename, size);
	}
	else {
		size = chunkSize;
		DPRINTF("Getting %s CRC by 0x%lx bytes\n", filename, size);
	}

	data = malloc( (size + 1) * sizeof(unsigned char) );
	if (!data) {
		fprintf(stderr, "Error: Cannot allocate memory for data\n");
		return 0;
	}

	/* CRC Initial value */
	ret = 0xFFFFFFFF;
	while ((rc = read(fd, data, size)) > 0) {
                ret = crc32_block(data, rc, ret);
		DPRINTF("Block size %d bytes: %" PRIx32 "\n", rc, ret);
		memset(data, 0, size);
	}

	free(data);

	return ret ^ 0xFFFFFFFF;
}

#ifdef TEST_CRC
int getCRCOutput(char *command, uint32_t *crc)
{
	FILE *fp;
	char out[16] = { 0 };

	fp = popen(command, "r");
	if (!fp)
		return -1;
	fgets(out, sizeof(out), fp);
	fclose(fp);

	*crc = (uint32_t) strtoll( (const char *)out, NULL, 16);
	return 0;
}

int main()
{
	uint32_t crc1 = 0, crc2 = 0;

	system("dd if=/dev/urandom of=/tmp/testcrc.tmp bs=1M count=10 2> /dev/null");
	DPRINTF("File size: 10M\n");

	if (getCRCOutput("crc32 /tmp/testcrc.tmp", &crc1) != 0)
		return 1;

	crc2 = crc32_file("/tmp/testcrc.tmp", -1);
	DPRINTF("test in once: %" PRIx32 "\n",	crc2);
	if (crc1 != crc2)
		return 2;

	crc2 = crc32_file("/tmp/testcrc.tmp", 1 << 10);
	DPRINTF("test by 1kB: %" PRIx32 "\n",	crc2);
	if (crc1 != crc2)
		return 3;

	crc2 = crc32_file("/tmp/testcrc.tmp", 512 * (1 << 10));
	DPRINTF("test by 512 kB: %" PRIx32 "\n", crc2);
	if (crc1 != crc2)
		return 4;

	crc2 = crc32_file("/tmp/testcrc.tmp", (1 << 20));
	DPRINTF("test by 1MB: %" PRIx32 "\n",	crc2);
	if (crc1 != crc2)
		return 5;

	crc2 = crc32_file("/tmp/testcrc.tmp", 5 * (1 << 20));
	DPRINTF("test by 5MB: %" PRIx32 "\n",	crc2);
	if (crc1 != crc2)
		return 6;


	unlink("/tmp/testcrc.tmp");
	DPRINTF("All tests passed\n");
	return 0;
}
#endif
