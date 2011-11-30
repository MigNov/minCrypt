/*
 *  byteops.c: byte operations used by mincrypt system's asymmetric approach
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#define DEBUG_BYTEOPS

#include "mincrypt.h"

#ifdef DEBUG_BYTEOPS
#define DPRINTF(fmt, args...) \
do { fprintf(stderr, "[mincrypt/byteops   ] " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

uint64_t bits_to_num(char *bits, int num)
{
	int i;
	uint64_t ret = 0;
	int append_bits = 0;
	char *pbits = NULL;

	if (num > 64) {
		DPRINTF("%s: Num is too big (%d), trimming to 64\n", __FUNCTION__, num);
		num = 64;
	}

	if (strlen(bits) > num)
		bits[ num - 1] = 0;

	if (strlen(bits) < num) {
		append_bits = num - strlen(bits);
		DPRINTF("%s: append_bits is %d\n", __FUNCTION__, append_bits);
		if (append_bits > 0) {
			pbits = (char *)malloc( (num+1) * sizeof(char) );
			DPRINTF("%s: Allocating %d bytes\n", __FUNCTION__, num);
			strcat(pbits, bits);
			for (i = 0; i < append_bits; i++)
				strcat(pbits, "0");
		}
	}
	else
		pbits = strdup(bits);

	DPRINTF("%s: pBits set to '%s' (%d bits)\n", __FUNCTION__, pbits, strlen(pbits));

	for (i = num; i > 0; i--) {
		if (pbits[i-1] == '1')
			ret += pow(2, (num - 1) - (i - 1));
	}
	free(pbits);

	DPRINTF("%s('%s', %d) returning 0x%" PRIx64 "\n", __FUNCTION__, bits, num, ret);
	return ret;
}

char *num_to_bits(uint64_t code, int *out_bits)
{
	int i = 0;
	int num_bits = 0;
	char *bits = NULL;
	uint64_t tmpcode = 0;

	while (tmpcode < code)
		tmpcode = pow(2, i++);

	num_bits = i - 1;

	if (out_bits != NULL)
		*out_bits = num_bits;

	bits = (char *)malloc((num_bits + 2) * sizeof(char));
	memset(bits, 0, num_bits + 1);
	for (i = num_bits - 1; i >= 0; i--)
		strcat(bits, (code & (uint64_t)pow(2, i)) ? "1" : "0");

	DPRINTF("%s(0x%" PRIx64 ", ...) returning '%s' (%d bits)\n", __FUNCTION__, code, bits, num_bits);
	return bits;
}

char *align_bits(char *bits, int num)
{
	uint64_t u64;
	char *obits = NULL;

	DPRINTF("%s: Aligning to %d bits\n", __FUNCTION__, num);

	u64 = bits_to_num( bits, num );
	obits = num_to_bits( u64, &num );

	if (num < 0)
		return bits;

	DPRINTF("%s: Aligned to %d bits\n", __FUNCTION__, num);

	return obits;
}

int get_number_of_bits_set(char *bits, int flags)
{
	int i, num = 0;

	for (i = 0; i < strlen(bits); i++) {
		if (((bits[i] == '0') && (flags & BIT_UNSET))
			|| ((bits[i] == '1') && flags & BIT_SET))
			num++;
	}

	return num;
}

int apply_binary_operation_on_byte(int tbit, int kbit, int operation)
{
	if (operation == BINARY_OPERATION_OR) {
		return ((tbit == '1') || (kbit == '1')) ? '1' : '0';
	}
	else
	if (operation == BINARY_OPERATION_AND) {
		return ((tbit == '1') && (kbit == '1')) ? '1' : '0';
	}
	else
	if (operation == BINARY_OPERATION_XOR) {
		return (((tbit == '0') && (kbit == '1'))
				|| ((tbit == '1') && (kbit == '0'))) ? '1' : '0';
	}

	return '?';
}

char *apply_binary_operation(char *tbits, char *kbits, int operation)
{
	int i;
	char *out = NULL;

	if (strlen(tbits) != strlen(kbits)) {
		DPRINTF("%s: Fatal error! Text bits != key bits!\n", __FUNCTION__);
		return NULL;
	}

	DPRINTF("%s: Applying %s operation on text and key pattern\n",
		__FUNCTION__, (operation == BINARY_OPERATION_OR) ? "OR" :
			((operation == BINARY_OPERATION_AND) ? "AND" :
			((operation == BINARY_OPERATION_XOR) ? "XOR" : "UNKNOWN")));

	out = (char *)malloc( (strlen(tbits)+1) * sizeof(char));
	memset(out, 0, strlen(tbits)+1);

	for (i = 0; i < strlen(tbits); i++)
		out[i] = apply_binary_operation_on_byte(tbits[i], kbits[i], operation);

	return out;
}

char *dec_to_hex(int dec)
{
	char buf[256] = { 0 };

	snprintf(buf, sizeof(buf), "%02x", dec);
	return strdup(buf);
}

uint64_t pow_and_mod(uint64_t n, uint64_t e, uint64_t mod)
{
	uint64_t i;
	uint64_t val = n;

	for (i = 1; i < e; i++) {
		val *= n;

		if (val > mod)
			val %= mod;
	}

	return val;
}

