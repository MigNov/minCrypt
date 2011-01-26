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
int _vectorSize = 0;

int getNearestPowerOfTwo(int value, int *oBits)
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

int crypt_set_password(char *salt, char *password, int vectorMultiplier)
{
	uint32_t shift = 0, val = 0, iSalt = 0, initial = 0;
	uint64_t shifts = 0, initialValue = 0, tmp = 0;
	int num = 0, lenSalt, lenPass, i, vectorMult, bits, passSum;
	char *savedpass;

	vectorMult = (vectorMultiplier < 0) ? DEFAULT_VECTOR_MULT : vectorMultiplier;

	lenSalt = strlen(salt);
	lenPass = strlen(password);
	_vectorSize = lenSalt * lenPass * vectorMult;

	getNearestPowerOfTwo(BUFFER_SIZE, &bits);
	DPRINTF("Chunk is encoded on %d bits\n", bits);

	while (val = *salt++)
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
		_iv = realloc( _iv, _vectorSize * sizeof(uint32_t) );
	else
		_iv = malloc( _vectorSize * sizeof(uint32_t) );

	for (i = 0; i < _vectorSize; i++) {
		val = savedpass[i % strlen(savedpass)];
		_iv[i] = (initial
					+ iSalt
					+ (uint32_t)pow( savedpass[(passSum - val) % strlen(savedpass) ], (passSum + i) / val)
				 );

		//DPRINTF("Got initialization vector %d: %08" PRIx32"\n", i, _iv[i]);
		initialValue += _iv[i];
	}
	free(savedpass);

	DPRINTF("%s: Vector generated, elements: %d\n", __FUNCTION__, _vectorSize);

	_ival = initial + initialValue;
	DPRINTF("%s: initialValue = 0x%"PRIx64"\n", __FUNCTION__, _ival);
}

int crypt_cleanup()
{
	_ival = 0;
	_vectorSize = 0;
	free(_iv);
}

char *crypt_encrypt(unsigned char *block, int size, uint32_t crc, int id, int *newSize)
{
	int i;
	uint32_t old_crc = 0;
	unsigned char *out = NULL;
	unsigned char data[4] = { 0 };
	int csize = size;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		if (newSize != NULL)
			*newSize = -1;
		return NULL;
	}

	if (crc == 0) {
		/* We make the output block 4 bytes bigger to carry the CRC-32 value */
		csize += 4;
		old_crc = crc32_block(block, size, 0xFFFFFFFF);
		DPRINTF("%s: Block CRC = 0x%08"PRIx32"\n", __FUNCTION__, old_crc);
	}
	else
		old_crc = crc;

	out = malloc( csize * sizeof(unsigned char) );
	memset(out, 0, csize);
	if (out == NULL) {
		DPRINTF("%s: Cannot allocate %d bytes of memory\n", __FUNCTION__, csize);
		return NULL;
	}

	for (i = 0; i < size; i++)
		out[i] = (_ival - old_crc - (_iv[i % _vectorSize] << ((id * size) + i))) - block[i];

	if (crc == 0) {
		UINT32STR(data, old_crc);
		out[i++] = data[0];
		out[i++] = data[1];
		out[i++] = data[2];
		out[i++] = data[3];
	}

	if (newSize != NULL)
		*newSize = csize;

	return out;
}

char *crypt_decrypt(unsigned char *block, int size, int crc, int id, int *newSize)
{
	unsigned char data[4] = { 0 }, *out = NULL;
	uint32_t old_crc = 0, new_crc = 0;
	unsigned int csize = size;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		if (newSize != NULL)
			*newSize = -1;
		return NULL;
	}

	data[0] = block[size - 4];
	data[1] = block[size - 3];
	data[2] = block[size - 2];
	data[3] = block[size - 1];
	old_crc = GETUINT32(data);

	out = crypt_encrypt(block, size-(crc ? 4 : 0), old_crc, id, &csize);

	new_crc = crc32_block(out, csize, 0xFFFFFFFF);
	DPRINTF("%s: Checking CRC value for %d byte-block (0x%08"PRIx32" [expected] %c= 0x%08"PRIx32" [found])\n",
			__FUNCTION__, size - (crc ? 4 : 0), old_crc, old_crc == new_crc ? '=' : '!', new_crc);

	if (old_crc != new_crc) {
		free(out);
		if (newSize != NULL)
			*newSize = -1;

		DPRINTF("%s: CRC value doesn't match!\n", __FUNCTION__);
		return NULL;
	}

	if (newSize != NULL)
		*newSize = csize;

	return out;
}

int crypt_encrypt_file(char *filename1, char *filename2, char *salt, char *password, int vectorMult)
{
	unsigned char buf[BUFFER_SIZE] = { 0 };
	char *outbuf;
	int fd, fdOut, rc, id, ret = 0;

	if ((salt != NULL) && (password != NULL))
		crypt_set_password(salt, password, vectorMult);

	DPRINTF("%s: Encrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename1);
		return 1;
	}
	fdOut = open(filename2, O_WRONLY | O_LARGEFILE | O_TRUNC | O_CREAT, 0644);
	if (fdOut < 0) {
		DPRINTF("%s: Cannot open file %s for writing\n", filename2);
		return 2;
	}

	id = 1;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		outbuf = crypt_encrypt(buf, rc, 0, id++, &rc);
		write(fdOut, outbuf, rc);
		free(outbuf);
	}

	close(fd);
	close(fdOut);

	DPRINTF("%s: Encryption done with code %d\n", __FUNCTION__, ret);
	return ret;
}

int crypt_decrypt_file(char *filename1, char *filename2, char *salt, char *password, int vectorMult)
{
	unsigned char buf[BUFFER_SIZE + 4] = { 0 };
	char *outbuf;
	int fd, fdOut, rc, id, ret = 0;

	if ((salt != NULL) && (password != NULL))
		crypt_set_password(salt, password, vectorMult);

	DPRINTF("%s: Decrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename1);
		return 1;
	}
	fdOut = open(filename2, O_WRONLY | O_LARGEFILE | O_TRUNC | O_CREAT, 0644);
	if (fdOut < 0) {
		DPRINTF("%s: Cannot open file %s for writing\n", filename2);
		return 2;
	}

	id = 1;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		outbuf = crypt_decrypt(buf, rc, 1, id++, &rc);
		if (rc == -1) {
			fprintf(stderr, "An error occured while decrypting input. Please check your password.\n");
			free(outbuf);
			close(fdOut);
			fdOut = -1;
			ret = 3;
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

int main(int argc, char *argv[])
{
	char *infile, *outfile, *tmp;
	char salt[1024] = { 0 }, password[1024] = { 0 };
	int decrypt = 0, nextIdx = 1, ret = 0, vectorMult = -1;//0x40;
	
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
		
	if (!decrypt)
	    ret = crypt_encrypt_file(infile, outfile, password, salt, vectorMult);
	else
	    ret = crypt_decrypt_file(infile, outfile, password, salt, vectorMult);
	    
	crypt_cleanup();
	
	return ret;
}

