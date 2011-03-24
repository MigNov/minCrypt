/*
 *  mincrypt.c: Minimalistic encryption system core
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
do { fprintf(stderr, "mincrypt: " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

uint32_t *_iv = NULL;
uint64_t _ival = 0;
int _vector_size = 0;
int out_type = OUTPUT_TYPE_BINARY;

/*
	Private function name:	get_nearest_power_of_two
	Since version:			0.0.1
	Description:			This private function is used to get the nearest higher power of two to the value, it's also returning number of bits used for the number returned in oBits variable
	Arguments:				@value [int]: value to which find the nearest power of two
							@oBits [int]: number of bits used by the return value as it's power of two
	Returns:				nearest higher power of two to value
*/
int get_nearest_power_of_two(int value, int *oBits)
{
	int bits = 0, val = 1;

	while (1) {
		if (val > value)
			break;

		val *= 2;
		bits++;
	}

	if (oBits != NULL)
		*oBits = bits-1;

	return val;
}

/*
	Function name:			crypt_set_output_type
	Since version:			0.0.1
	Description:			This function is used to set type of output encoding
	Arguments:				@type [int]: type number, can be either OUTPUT_TYPE_BINARY (i.e. no encoding) or OUTPUT_TYPE_BASE64 to use base64 encoding
	Returns:				0 for no error, otherwise error code
*/
int crypt_set_output_type(int type)
{
	if ((type < OUTPUT_TYPE_BASE) || (type > OUTPUT_TYPE_BASE64))
		return 1;

	out_type = type;
	return 0;
}

/*
	Function name:			crypt_set_password
	Since version:			0.0.1
	Description:			This function is used to calculate initialization vectors (IV) from the password and salt values
	Arguments:				@salt [string]: salt value to be used for the IV generation
							@password [string]: password to be used for IV generation
							@vector_multiplier [int]: value to extend the vector by multiplicating it's size
	Returns:				None
*/
void crypt_set_password(char *salt, char *password, int vector_multiplier)
{
	uint32_t shift = 0, val = 0, iSalt = 0, initial = 0;
	uint64_t shifts = 0, initialValue = 0, tmp = 0;
	int num = 0, lenSalt, lenPass, i, vector_mult, bits, passSum;
	char *savedpass;

	vector_mult = (vector_multiplier < 0) ? DEFAULT_VECTOR_MULT : vector_multiplier;

	lenSalt = strlen(salt);
	lenPass = strlen(password);
	_vector_size = lenSalt * lenPass * vector_mult;

	get_nearest_power_of_two(BUFFER_SIZE, &bits);
	DPRINTF("Chunk is encoded on %d bits\n", bits);

	while (val = (*salt++))
		iSalt = pow(val, ++num) * bits;

	DPRINTF("%s: iSalt = 0x%"PRIx32"\n", __FUNCTION__, iSalt);

	num = 0;
	savedpass = strdup(password);
	passSum = 0;
	while (val = *password++) {
		passSum += val;
		initial += (val + iSalt) << ++num;
	}

	DPRINTF("%s: initial = 0x%"PRIx32"\n", __FUNCTION__, initial);

	if (_iv != NULL)
		_iv = realloc( _iv, _vector_size * sizeof(uint32_t) );
	else
		_iv = malloc( _vector_size * sizeof(uint32_t) );

	for (i = 0; i < _vector_size; i++) {
		val = savedpass[i % strlen(savedpass)];
		_iv[i] = (initial
					+ iSalt
					+ (uint32_t)pow( savedpass[(passSum - val) % strlen(savedpass) ], (passSum + i) / val)
				 );

		//DPRINTF("Got initialization vector %d: %08" PRIx32"\n", i, _iv[i]);
		initialValue += _iv[i];
	}
	free(savedpass);

	DPRINTF("%s: Vector generated, elements: %d\n", __FUNCTION__, _vector_size);

	_ival = initial + initialValue;
	DPRINTF("%s: initialValue = 0x%"PRIx64"\n", __FUNCTION__, _ival);
}

/*
	Function name:			crypt_cleanup
	Since version:			0.0.1
	Description:			This function is used to cleanup all the memory allocated by crypt_set_password() function
	Arguments:				None
	Returns:				None
*/
void crypt_cleanup()
{
	_ival = 0;
	_vector_size = 0;
	free(_iv);
}

/*
	Private function name:	crypt_process
	Since version:			0.0.1
	Description:			This function is used to process the encryption and decryption of the data block
	Arguments:				@block [buffer]: buffer of data to be encrypted/decrypted
							@size [int]: size of buffer
							@crc [uint32_t]: CRC value for the data block (used as a part of algorithm)
							@id [int]: identifier of the chunk to be encoded (used as a part of algorithm)
	Returns:				output buffer of identical length as original
*/
static unsigned char *crypt_process(unsigned char *block, int size, uint32_t crc, int id)
{
	int i;
	unsigned char *out = NULL;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		return NULL;
	}

	if (size <= 0) {
		DPRINTF("%s: Invalid size of %d\n", __FUNCTION__, size);
		return NULL;
	}

	out = (unsigned char *)malloc( (size + 1) * sizeof(unsigned char) );
	if (out == NULL) {
		DPRINTF("%s: Cannot allocate %d bytes of memory\n", __FUNCTION__, size + 1);
		return NULL;
	}

	memset(out, 0, size);

	for (i = 0; i < size; i++)
		out[i] = (_ival - crc - (_iv[i % _vector_size] << ((id * size) + i))) - block[i];

	return out;
}

/*
	Function name:			crypt_encrypt
	Since version:			0.0.1
	Description:			Main function for the data encryption. Takes the block, size and id as input arguments with returning new size
	Arguments:				@block [buffer]: buffer of data to be encrypted/decrypted
							@size [int]: size of buffer
							@id [int]: identifier of the chunk to be encoded
							@new_size [size_t]: output integer value for the output buffer size
	Returns:				output buffer of new_size bytes
*/
unsigned char *crypt_encrypt(unsigned char *block, int size, int id, size_t *new_size)
{
	int i;
	uint32_t crc = 0;
	unsigned char *out = NULL, *tmp = NULL;
	unsigned char data[4] = { 0 };
	int csize = size, start_pos = 0;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		if (new_size != NULL)
			*new_size = -1;
		return NULL;
	}

	crc = crc32_block(block, size, 0xFFFFFFFF);
	DPRINTF("Block CRC-32 value: 0x%"PRIx32"\n", crc);

	tmp = crypt_process(block, size, crc, id);
	if (tmp == NULL)
		return NULL;

	if (out_type == OUTPUT_TYPE_BASE64) {
		int orig_size = size;
		unsigned char *tmp2 = NULL;

		DPRINTF("%s: Original size is %d bytes\n", __FUNCTION__, orig_size);

		tmp2 = (unsigned char *)base64_encode( (const char *)tmp, &size);
		free(tmp);

		DPRINTF("%s: Encoded size is %d bytes\n", __FUNCTION__, size);

		csize = size + 13;

                out = malloc( csize * sizeof(unsigned char) );
                memset(out, 0, csize);

                out[0] = out_type;
                DPRINTF("%s: Saving out_type 0x%02x to chunk position 0\n", __FUNCTION__, out_type);
                UINT32STR(data, (uint32_t)orig_size);
                memcpy(out+1, data, 4);
                DPRINTF("%s: Saving original size (%d) to chunk positions 1 - 4 = { %02x, %02x, %02x, %02x }\n",
                                __FUNCTION__, orig_size, out[1], out[2], out[3], out[4]);
                UINT32STR(data, (uint32_t)size);
                memcpy(out+5, data, 4);
                DPRINTF("%s: Saving new size (%d) to chunk positions 5 - 8 = { %02x, %02x, %02x, %02x }\n",
                                __FUNCTION__, size, out[5], out[6], out[7], out[8]);
		UINT32STR(data, (uint32_t)crc);
		memcpy(out+9, data, 4);
		DPRINTF("%s: Saving CRC (0x%"PRIx32") to chunk positions 9 - 12 = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, crc, out[9], out[10], out[11], out[12]);
                memcpy(out+13, tmp2, size);

                free(tmp2);
	}
	else
	if (out_type == OUTPUT_TYPE_BINARY) {
		csize = size + 13;

		out = malloc( csize * sizeof(unsigned char) );
		memset(out, 0, csize);

		out[0] = out_type;
		DPRINTF("%s: Saving out_type 0x%02x to chunk position 0\n", __FUNCTION__, out_type);
		UINT32STR(data, (uint32_t)size);
		memcpy(out+1, data, 4);
		DPRINTF("%s: Saving original size (%d) to chunk positions 1 - 4 = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, size, out[1], out[2], out[3], out[4]);
		DPRINTF("%s: Leaving positions 5 to 8 empty since they are reserved\n", __FUNCTION__);
		UINT32STR(data, (uint32_t)crc);
		memcpy(out+9, data, 4);
		DPRINTF("%s: Saving CRC (0x%"PRIx32") to chunk positions 9 - 12 = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, crc, out[9], out[10], out[11], out[12]);
		memcpy(out+13, tmp, size);
		DPRINTF("%s: Saving %d bytes to the end of the stream\n", __FUNCTION__, size);

		free(tmp);
	}

	if (new_size != NULL) {
		DPRINTF("%s: New size is %"PRIi32"\n", __FUNCTION__, csize);
		*new_size = csize;
	}

	return out;
}

/*
	Function name:			crypt_decrypt
	Since version:			0.0.1
	Description:			Main function for the data decryption. Takes the block, size and id as input arguments with returning both decrypted encoded and decrypted decoded (raw) size
	Arguments:				@block [buffer]: buffer of data to be encrypted/decrypted
							@size [int]: size of buffer
							@id [int]: identifier of the chunk to be encoded
							@new_size [size_t]: output integer value for the output buffer size
							@read_size [int]: output integer value for the decoded output buffer size (different from new_size in case of base64 encoding)
	Returns:				output buffer of read_size bytes
*/
unsigned char *crypt_decrypt(unsigned char *block, int size, int id, size_t *new_size, int *read_size)
{
	unsigned char data[4] = { 0 }, *out = NULL;
	uint32_t old_crc = 0, new_crc = 0;
	uint32_t csize = size;
	unsigned int i, enc_size = 0, orig_size = 0;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		if (new_size != NULL)
			*new_size = -1;
		return NULL;
	}

	if (size == 0) {
		if (new_size != NULL)
			*new_size = -1;
		return NULL;
	}

	out_type = block[0];

	DPRINTF("%s: Found type 0x%02x [%s]\n", __FUNCTION__, out_type, (out_type == OUTPUT_TYPE_BASE64) ? "base64" : "binary" );
	DPRINTF("%s: Input size is %d\n", __FUNCTION__, size);

	data[0] = block[1];
	data[1] = block[2];
	data[2] = block[3];
	data[3] = block[4];
	orig_size = GETUINT32(data);
	DPRINTF("%s: Original chunk size is %d bytes\n", __FUNCTION__, orig_size);

	data[0] = block[5];
	data[1] = block[6];
	data[2] = block[7];
	data[3] = block[8];
	enc_size = GETUINT32(data);
	DPRINTF("%s: Encoded chunk size is %d bytes\n", __FUNCTION__, size);

	data[0] = block[9];
	data[1] = block[10];
	data[2] = block[11];
	data[3] = block[12];
	old_crc = GETUINT32(data);
	DPRINTF("%s: Original CRC-32 value is 0x%"PRIx32"\n", __FUNCTION__, old_crc);

	if (out_type == OUTPUT_TYPE_BINARY) {
		out = crypt_process(block+13, orig_size, old_crc, id);
		if (out == NULL)
			return NULL;

		csize = orig_size;
	}
	else
	if (out_type == OUTPUT_TYPE_BASE64) {
		unsigned char *tmp = NULL;

		tmp = (unsigned char *)base64_decode( (const char *)block+13, &size);
		tmp[ orig_size ] = 0;

		out = crypt_process(tmp, orig_size, old_crc, id);
		if (out == NULL)
			return NULL;

		csize = orig_size;
	}

	DPRINTF("%s: Got chunk size of %d bytes\n", __FUNCTION__, csize);

	new_crc = crc32_block(out, orig_size, 0xFFFFFFFF);
	DPRINTF("%s: Checking CRC value for %d byte-block (0x%08"PRIx32" [expected] %c= 0x%08"PRIx32" [found])\n",
			__FUNCTION__, orig_size, old_crc, old_crc == new_crc ? '=' : '!', new_crc);

	if (old_crc != new_crc) {
		free(out);
		if (new_size != NULL)
			*new_size = -1;

		DPRINTF("%s: CRC value doesn't match!\n", __FUNCTION__);
		return NULL;
	}

	if (new_size != NULL)
		*new_size = csize;

	if (read_size != NULL)
		*read_size = (enc_size > 0) ? enc_size : csize;

	return out;
}

/*
	Function name:			crypt_encrypt_file
	Since version:			0.0.1
	Description:			Function for the entire file encryption. Takes the input and output files, salt, password and vector_multiplier value
	Arguments:				@filename1 [string]: input (original) file
							@filename2 [string]: output (encrypted) file
							@salt [string]: salt value to be used, may be NULL to use already set IVs if applicable, used only with conjuction password
							@password [string]: password value to be used, may be NULL to use already set IVs if applicable, used only with conjuction salt
							@vector_multiplier [int]: vector multiplier value, can be 0, used only if salt and password are set
	Returns:				0 for no error, otherwise error code
*/
int crypt_encrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier)
{
	unsigned char buf[BUFFER_SIZE] = { 0 };
	char *outbuf;
	int fd, fdOut, rc, id, ret = 0, errno_saved;

	if ((salt != NULL) && (password != NULL))
		crypt_set_password(salt, password, vector_multiplier);

	DPRINTF("%s: Encrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		errno_saved = errno;
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename1);
		return -errno_saved;
	}
	fdOut = open(filename2, O_WRONLY | O_LARGEFILE | O_TRUNC | O_CREAT, 0644);
	if (fdOut < 0) {
		errno_saved = errno;
		DPRINTF("%s: Cannot open file %s for writing\n", filename2);
		return -errno;
	}

	id = 1;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		outbuf = crypt_encrypt(buf, rc, id++, &rc);
		write(fdOut, outbuf, rc);
		free(outbuf);
	}

	close(fd);
	close(fdOut);

	DPRINTF("%s: Encryption done with code %d\n", __FUNCTION__, ret);
	return ret;
}

/*
	Function name:			crypt_decrypt_file
	Since version:			0.0.1
	Description:			Function for the entire file decryption. Takes the input and output files, salt, password and vector_multiplier value
	Arguments:				@filename1 [string]: input (encrypted) file
							@filename2 [string]: output (decrypted) file
							@salt [string]: salt value to be used, may be NULL to use already set IVs if applicable, used only with conjuction password
							@password [string]: password value to be used, may be NULL to use already set IVs if applicable, used only with conjuction salt
							@vector_multiplier [int]: vector multiplier value, can be 0, used only if salt and password are set
	Returns:				0 for no error, otherwise error code
*/
int crypt_decrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier)
{
	unsigned char buf[BUFFER_SIZE_BASE64+13] = { 0 };
	char *outbuf;
	int fd, fdOut, rc, rsize, id, ret = 0;
	uint64_t already_read = 0;

	if ((salt != NULL) && (password != NULL))
		crypt_set_password(salt, password, vector_multiplier);

	DPRINTF("%s: Decrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename1);
		return -EPERM;
	}
	fdOut = open(filename2, O_WRONLY | O_LARGEFILE | O_TRUNC | O_CREAT, 0644);
	if (fdOut < 0) {
		DPRINTF("%s: Cannot open file %s for writing\n", filename2);
		return -EIO;
	}

	id = 1;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		outbuf = crypt_decrypt(buf, rc, id++, &rc, &rsize);
		already_read += rsize + 13;
		if (lseek(fd, already_read, SEEK_SET) != already_read)
			DPRINTF("Warning: Seek error!\n");
		if (rc == -1) {
			DPRINTF("An error occured while decrypting input. Please check your password.\n");
			free(outbuf);
			close(fdOut);
			fdOut = -1;
			ret = -EINVAL;
			unlink(filename2);
			break;
		}
		write(fdOut, outbuf, rc);
		free(outbuf);
	}

	if (fd != -1)
		close(fd);
	if (fdOut != -1)
		close(fdOut);

	DPRINTF("%s: Decryption done with code %d\n", __FUNCTION__, ret);
	return ret;
}

#ifndef NO_MAIN
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
#endif
