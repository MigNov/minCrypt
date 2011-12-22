/*
 *  mincrypt.c: Minimalistic encryption system core
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#define DEBUG_MINCRYPT

#include "mincrypt.h"

#ifdef WINDOWS
	#ifdef BUILDING_DLL
		#define DLLEXPORT __declspec(dllexport)
	#else
		#define DLLEXPORT __declspec(dllimport)
	#endif
#else
	#define DLLEXPORT	
#endif

#ifdef DEBUG_MINCRYPT
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[mincrypt/corelib     ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

uint32_t *_iv = NULL;
uint32_t *_ivn = NULL; // used for asymmetric approach
uint32_t *_iva = NULL; // used for asymmetric approach
uint64_t _ival = 0;
int _vector_size = 0;
int _avector_size = -1;// used for asymmetric approach
int type_approach = APPROACH_SYMMETRIC;
int out_type = ENCODING_TYPE_BINARY;
int simple_mode = 0;

/*
	Private function name:	get_nearest_power_of_two
	Since version:		0.0.1
	Description:		This private function is used to get the nearest higher power of two to the value, it's also returning number of bits used for the number returned in oBits variable
	Arguments:		@value [int]: value to which find the nearest power of two
				@oBits [int]: number of bits used by the return value as it's power of two
	Returns:		nearest higher power of two to value
*/
DLLEXPORT int get_nearest_power_of_two(int value, int *oBits)
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

tTokenizer tokenize_by(char *string, char *by)
{
	char *tmp = NULL;
	char *str = NULL;
	char *save = NULL;
	char *token = NULL;
	int i = 0;
	tTokenizer t;

	tmp = strdup(string);
	t.tokens = malloc( sizeof(char *) );
	save = NULL;
	for (str = tmp; ; str = NULL) {
		token = strtok_r(str, by, &save);
		if (token == NULL)
			break;

		t.tokens = realloc( t.tokens, (i + 1) * sizeof(char *) );
		t.tokens[i++] = strdup(token);
	}
	token = save;

	t.numTokens = i;

	return t;
}

tTokenizer tokenize(char *string)
{
	return tokenize_by(string, " ");
}

void free_tokens(tTokenizer t)
{
	int i;

	for (i = 0; i < t.numTokens; i++) {
		free(t.tokens[i]);
		t.tokens[i] = NULL;
	}
}

void write_header_footer(int fd, int isFooter, int private)
{
	char tmp[1024] = { 0 };

	snprintf(tmp, sizeof(tmp), " --- %sMINCRYPT %s KEY %s FOR %d-BIT KEYLENGTH ---\n",
			isFooter ? "END OF " : "",
			private ? "PRIVATE" : "PUBLIC",	PACKAGE_VERSION,
			#ifdef USE_64BIT_NUMBERS
			64
			#else
			32
			#endif
			);

	write(fd, tmp, strlen(tmp));
}

void write_data(int fd, unsigned char *data, int num)
{
	int i;
	char *a = NULL;

	for (i = 0; i < num; i++) {
		a = dec_to_hex(data[i]);
		write(fd, a, 2);
		free(a);

		if ((i + 1) % 32 == 0)
			write(fd, "\n", 1);
		else
		if ((i + 1) % 4 == 0)
			write(fd, " ", 1);
	}
}

int read_key_data(int fd, int bits, int isPrivate)
{
	int i, in, c, num;
	char buf[10] = { 0 };
	char tmp[16] = { 0 };
	char *endptr;
	uint32_t val;
	uint64_t val64;

	if (bits != 32)
		return -EINVAL;

	if ((_iva == NULL) || (_ivn == NULL))
		return -EIO;

	i = in = num = 0;
	while ((c = read(fd, buf, sizeof(buf) - 1)) > 0) {
		if (((buf[8] == ' ') || (buf[8] == '\n'))
			&& (strstr((const char *)buf, "END") == NULL)) {
			buf[8] = 0;
			snprintf(tmp, sizeof(tmp), "0x%s", buf);

			val = (uint32_t) strtol(tmp, &endptr, 16);

			if (num % 2 == 1) {
				_iva[i++] = val;
				_ival += val;
			}
			else {
				if (!isPrivate)
					_ivn[in++] = val;
				else {
					uint16_t p, q;

					p = (val >> 16);
					q = (val % 65536);

					get_decryption_value(p, q, 0, &val64);

					_ivn[in++] = (uint32_t)val64;
				}
			}

			num++;
		}
		memset(buf, 0, sizeof(buf));
	}

	return 0;
}

long get_version(char *verstr)
{
	char a[2] = { 0 };
	int major = -1;
	int minor = -1;
	int micro = -1;
	tTokenizer t;

	t = tokenize_by(verstr, ".");
	if (t.numTokens < 3)
		return -EINVAL;

	a[0] = t.tokens[0][0];
	major = atoi(a);
	a[0] = t.tokens[1][0];
	minor = atoi(a);
	a[0] = t.tokens[2][0];
	micro = atoi(a);

	DPRINTF("%s: Got version: major = %d, minor = %d, micro = %d\n", __FUNCTION__, major, minor, micro);

	return ((major << 16) + (minor << 8) + (micro));
}

int read_header_footer(int fd, int isFooter, int *isPrivate, int *bits)
{
	int c, bitlen;
	char a[2] = { 0 };
	char tmp[128] = { 0 };
	tTokenizer t;
	int ret = 0;

	while (((c = read(fd, a, 1)) == 2) || (a[0] != '\n'))
		strcat(tmp, a);

	t = tokenize(tmp);

	if (!isFooter && ((t.numTokens < 6) || (strcmp(t.tokens[0], t.tokens[ t.numTokens - 1 ]) != 0)
		|| (strcmp(t.tokens[0], "---") != 0) || (strcmp(t.tokens[1], "MINCRYPT") != 0)
		|| (strcmp(t.tokens[3], "KEY") != 0)))
		ret = -EINVAL;

	if (isPrivate != NULL)
		*isPrivate = (strcmp(t.tokens[2], "PRIVATE") == 0) ? 1 : 0;

	if (get_version(PACKAGE_VERSION) < get_version(t.tokens[4]))
		ret = -EINVAL;

	bitlen = atoi(t.tokens[6]);
#ifndef USE_64BIT_NUMBERS
	if (bitlen != 32)
		ret = -EINVAL;
#endif

	if (bits != NULL)
		*bits = bitlen;

	free_tokens(t);

	return ret;
}

/*
	Function name:		mincrypt_get_version
	Since version:		0.0.3
	Description:		The mincrypt_get_version() function is useful to get the long integer representation of version number.
	Arguments:		None
	Returns:		version number encoded as integer
*/
DLLEXPORT long mincrypt_get_version(void)
{
	return get_version(PACKAGE_VERSION);
}

/*
	Function name:		mincrypt_read_key_file
	Since version:		0.0.3
	Description:		This function is used to read the keyfile identified by keyfile string.
	Arguments:		@keyfile [string]: file with private or public key
				@isPrivate [out int]: output variable set to 1 if key file contains private key or 0 if it contains public key
	Returns:		0 for no error, -errno otherwise
*/
DLLEXPORT int mincrypt_read_key_file(char *keyfile, int *oIsPrivate)
{
	int fd;
	int isPrivate;
	int fileSize;
	int bits;
	int ret = 0;

	fd = open(keyfile, O_RDONLY);
	if (fd < 0)
		return -errno;

	fileSize = (int)lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if (read_header_footer(fd, 0, &isPrivate, &bits) != 0) {
		close(fd);
		return -EINVAL;
	}

	if (oIsPrivate != NULL)
		*oIsPrivate = isPrivate;

        _avector_size = ((fileSize - (56 + 59)) / 9) / 2;

	if (_iva != NULL)
		_iva = realloc( _iva, _avector_size * sizeof(uint32_t) );
	else
		_iva = malloc( _avector_size * sizeof(uint32_t) );

	if (_ivn != NULL)
		_ivn = realloc( _ivn, _avector_size * sizeof(uint32_t) );
	else
		_ivn = malloc( _avector_size * sizeof(uint32_t) );

	if ((_iva == NULL) || (_ivn == NULL)) {
		free(_iva);
		free(_ivn);
		ret = -ENOMEM;
	}
	else
	if (read_key_data(fd, bits, isPrivate) != 0)
		ret = -EINVAL;

	close(fd);

	if (ret != 0) {
		free(_ivn);
		free(_iva);
	}

	type_approach = APPROACH_ASYMMETRIC;
	return ret;
}

/*
	Function name:		mincrypt_generate_keys
	Since version:		0.0.3
	Description:		This function is used to generate the keyfiles and save them into key_private and key_public
	Arguments:		@bits [int]: number of bits used to generate the key files
				@salt [string]: salt to be used for the key generation
				@password [string]: password for key generation
				@key_private [string]: string identifying file where your new private key will be stored
				@key_public [string]: string identifying file where your new public key will be stored
	Returns:		0 for no error, -errno otherwise
*/
DLLEXPORT int mincrypt_generate_keys(int bits, char *salt, char *password, char *key_private, char *key_public)
{
	int fd, bit, i, num, ui, pi;
	int len, iter;
	int len2, iter2;
	uint64_t d, e, n;
	uint64_t tmp;
	uint64_t uSalt;
	uint64_t uPassword;
	uint64_t prime_sum;
	char *tbits = NULL;
	char *kbits = NULL;
	char *obits = NULL;
	unsigned char *data_pub = NULL;
	unsigned char *data_pk = NULL;
	unsigned char u32s[4];
	tPrimes primes;
	int ret = -EINVAL;
	int ITER_MAX = 4;
	int est_size = 0;
	uint64_t testVal = 65;
	uint64_t p = 0, q = 0;
	int bytes = 2;

	srand( time(NULL) / bits );

	#ifdef USE_64BIT_NYMBERS
	bytes = 4;
	#endif

	est_size = bytes * ((ITER_MAX * (bits / 8)) * 4);

	data_pub = (unsigned char *)malloc( est_size * sizeof(unsigned char) );
	memset(data_pub, 0, bits);
	data_pk = (unsigned char *)malloc( est_size * sizeof(unsigned char) );
	memset(data_pk, 0, bits);

	iter = len = ui = pi = 0;
	while (len < ITER_MAX) {
		iter++;

		tmp = 0;
		for (i = 0; i < strlen(salt); i++)
			tmp += (uint64_t) pow( 2, (salt[i]+iter) % 64 );

		DPRINTF("%s: Iteration #%d\n", __FUNCTION__, len+1);
		bit = rand() % 2;
		uSalt = find_nearest_prime_number(tmp, bit ? GET_NEAREST_BIGGER : GET_NEAREST_SMALLER);

		DPRINTF("%s: uSalt number is %"PRIi64"\n", __FUNCTION__, uSalt);

		kbits = num_to_bits( tmp, &num );
		DPRINTF("%s: Generated salt value of 0x%"PRIx64" (%d bits)\n", __FUNCTION__, tmp, num);

		tmp = 0;
		for (i = 0; i < strlen(password); i++)
			tmp += (uint64_t) pow( 2, (password[i]+iter) % 64 );

		bit = rand() % 2;
		uPassword = find_nearest_prime_number(tmp, bit ? GET_NEAREST_BIGGER : GET_NEAREST_SMALLER);

		tbits = num_to_bits( tmp, &num );
		DPRINTF("%s: Generated password value of 0x%"PRIx64" (%d bits)\n", __FUNCTION__, tmp, num);

		bit = rand() % 3;
		obits = apply_binary_operation(tbits, align_bits(kbits, num), bit);
		if (obits == NULL) {
			DPRINTF("%s: obits is NULL, skipping ...\n", __FUNCTION__);
			continue;
		}
		free(tbits);
		free(kbits);

		tmp = bits_to_num(obits, num);
		free(obits);
		DPRINTF("%s: tmp value is 0x%"PRIx64" (%d bits)\n", __FUNCTION__, tmp, num);

		primes = get_prime_elements(tmp);
		prime_sum = 0;
		for (i = 0; i < primes.num; i++)
			prime_sum += primes.numbers[i];

		prime_sum <<= primes.num;
		free_primes(primes);

		bit = rand() % 2;
		tbits = num_to_bits( prime_sum, &num );
		prime_sum += (tmp << (get_number_of_bits_set(tbits, bit) % num));
		DPRINTF("%s: prime sum = 0x%"PRIx64"\n", __FUNCTION__, prime_sum);
		free(tbits);

		len2 = iter2 = 0;
		while (len2 < (bits / 8)) {
			iter2++;
			bit = rand() % 2;
			p = uPassword - iter2;
			q = uSalt / (iter2 + iter);
			if (get_random_values( prime_sum % time(NULL), bits, &p, &q, &e, &d, &n, bit) < 0) {
				DPRINTF("%s: Cannot get the random values based on the input data\n", __FUNCTION__);
				//goto cleanup;
				continue;
			}

			DPRINTF("%s: e = %"PRIu64", d = %"PRIu64", n = %"PRIu64"\n", __FUNCTION__, e, d, n);
			testVal = time(NULL) % 256;
			if ((d == 0) || (asymmetric_decrypt_u64(asymmetric_encrypt_u64( testVal, e, n), d, n) != testVal )) {
				DPRINTF("%s: Test decryption applied to the encrypted text failed!\n", __FUNCTION__);
				//goto cleanup;
				continue;
			}

#ifdef USE_64BIT_NUMBERS
			#error "Keys with 64-bit numbers are not supported yet"
#else
			/* Write n to public key */
			UINT32STR(u32s, (uint32_t)n);
			for (i = 0; i < 4; i++)
				data_pub[ui++] = u32s[i];

			/* Write encoded prime components to private key */
			UINT32STR(u32s, (uint32_t)(((uint16_t)p << 16) + ((uint16_t)q)) );
			for (i = 0; i < 4; i++)
				data_pk[pi++] = u32s[i];

			/* Write e to public key */
			UINT32STR(u32s, (uint32_t)e);
			for (i = 0; i < 4; i++)
				data_pub[ui++] = u32s[i];

			/* Write d to private key */
			UINT32STR(u32s, (uint32_t)d);
			for (i = 0; i < 4; i++)
				data_pk[pi++] = u32s[i];
#endif

			len2++;

			DPRINTF("%s: Test passed, pi is %d, ui is %d\n", __FUNCTION__, pi, ui);
		}

		len++;
	}

	DPRINTF("%s: All tests passed, private key length is %d, public key length is %d\n", __FUNCTION__, pi, ui);

	/* Save private key */
	unlink(key_private);
	fd = open(key_private, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	write_header_footer(fd, 0, 1);
	if (fd < 0) {
		DPRINTF("%s: Cannot create private key file\n", __FUNCTION__);
		goto cleanup;
	}
	write_data(fd, data_pk, pi);
	write_header_footer(fd, 1, 1);
	close(fd);

	DPRINTF("%s: Private key file '%s' written\n", __FUNCTION__, key_private);

	/* Save public key */
	unlink(key_public);
	fd = open(key_public, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	write_header_footer(fd, 0, 0);
	if (fd < 0) {
		DPRINTF("%s: Cannot create public key file\n", __FUNCTION__);
		goto cleanup;
	}
	write_data(fd, data_pub, ui);
	write_header_footer(fd, 1, 0);
	close(fd);

	DPRINTF("%s: Public key file '%s' written\n", __FUNCTION__, key_public);

	ret = 0;
cleanup:
	free(data_pub);
	data_pub = NULL;
	free(data_pk);
	data_pk = NULL;

	return ret;
}

/*
	Function name:		mincrypt_dump_vectors
	Since version:		0.0.3
	Description:		This function is used to dump the initialization vectors and save them into a file
	Arguments:		@dump_file [string]: a file to store the dump to
	Returns:		0 for no error, -errno otherwise
*/
DLLEXPORT void mincrypt_dump_vectors(char *dump_file)
{
	int fd, num = 0;
	char data[1024] = { 0 };

	fd = open(dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;

	snprintf(data, sizeof(data), "--- MINCRYPT %s DUMP DATA ---\n\n", PACKAGE_VERSION);
	write(fd, data, strlen(data));

	if (_iv != NULL) {
		snprintf(data, sizeof(data), "--- INITIALIZATION VECTORS _IV ---\n");
		write(fd, data, strlen(data));
		write_data(fd, (void *)_iv, _vector_size);
		num++;
	}
	if (_ivn != NULL) {
		snprintf(data, sizeof(data), "--- INITIALIZATION VECTORS _IVN ---\n");
		write(fd, data, strlen(data));
		write_data(fd, (void *)_ivn, _avector_size);
		num++;
	}
	if (_iva != NULL) {
		snprintf(data, sizeof(data), "--- INITIALIZATION VECTORS _IVA ---\n");
		write(fd, data, strlen(data));
		write_data(fd, (void *)_iva, _avector_size);
		num++;
	}

	close(fd);

	DPRINTF("%s: All (%d) initialization vectors saved to %s\n", __FUNCTION__, num, dump_file);
}

/*
	Function name:		mincrypt_set_encoding_type
	Since version:		0.0.1
	Description:		This function is used to set type of output encoding
	Arguments:		@type [int]: type number, can be either ENCODING_TYPE_BINARY (i.e. no encoding) or ENCODING_TYPE_BASE64 to use base64 encoding
	Returns:		0 for no error, otherwise error code (1 for unsupported encoding and 2 for enabling simple mode for non-binary encoding)
*/
DLLEXPORT int mincrypt_set_encoding_type(int type)
{
	if ((type < ENCODING_TYPE_BASE) || (type > ENCODING_TYPE_BASE64))
		return 1;

	if (simple_mode && (type != ENCODING_TYPE_BINARY))
		return 2;

	out_type = type;
	return 0;
}

/*
	Function name:		mincrypt_set_simple_mode
	Since version:		0.0.1
	Description:		This function is used to enable or disable simple mode on the decryption phase. Simple mode is the mode where CRC-32 checking and read size checking are disabled. Other encoding than binary encoding cannot work in this mode.
	Arguments:		@enable [int]:	enable (1) or disable (0) simple mode checking code for decryption phase
	Returns:		0 on success, 1 on error (trying to set simple mode on non-binary encoding)
*/
DLLEXPORT int mincrypt_set_simple_mode(int enable)
{
	if ((out_type != ENCODING_TYPE_BINARY) && (enable != 0))
		return 1;

	simple_mode = enable;
	return 0;
}

/*
	Function name:		mincrypt_set_password
	Since version:		0.0.1
	Description:		This function is used to calculate initialization vectors (IV) from the password and salt values
	Arguments:		@salt [string]: salt value to be used for the IV generation
				@password [string]: password to be used for IV generation
				@vector_multiplier [int]: value to extend the vector by multiplicating it's size
	Returns:		None
*/
DLLEXPORT void mincrypt_set_password(char *salt, char *password, int vector_multiplier)
{
	uint32_t val = 0, iSalt = 0, initial = 0;
	uint64_t initialValue = 0;
	int num = 0, lenSalt, lenPass, i, vector_mult, bits, passSum;
	char *savedpass;

	vector_mult = (vector_multiplier < 0) ? DEFAULT_VECTOR_MULT : vector_multiplier;

	lenSalt = strlen(salt);
	lenPass = strlen(password);
	_vector_size = lenSalt * lenPass * vector_mult;

	get_nearest_power_of_two(BUFFER_SIZE, &bits);
	DPRINTF("Chunk is encoded on %d bits\n", bits);

	while ((val = *(salt++)) && (salt != NULL))
		iSalt = pow(val, ++num) * bits;

	DPRINTF("%s: iSalt = 0x%"PRIx32"\n", __FUNCTION__, iSalt);

	num = 0;
	savedpass = strdup(password);
	passSum = 0;
	while ((val = *password++) && (password != NULL)) {
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
		_iv[i] = (initialValue % UINT32_MAX) + (initial
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

	if (_avector_size == -1)
		type_approach = APPROACH_SYMMETRIC;
}

/*
	Function name:		mincrypt_cleanup
	Since version:		0.0.1
	Description:		This function is used to cleanup all the memory allocated by crypt_set_password() function
	Arguments:		None
	Returns:		None
*/
DLLEXPORT void mincrypt_cleanup(void)
{
	_ival = 0;
	if (_iv != NULL)
		free(_iv);
	if (_iva != NULL)
		free(_iva);
	if (_ivn != NULL)
		free(_ivn);
}

/*
	Private function name:	mincrypt_process
	Since version:		0.0.1
	Description:		This function is used to process the encryption and decryption of the data block
	Arguments:		@block [buffer]: buffer of data to be encrypted/decrypted
				@size [int]: size of buffer
				@decrypt [int]: boolean whether to encrypt or decrypt (0 = encrypt, 1 = decrypt)
				@crc [uint32_t]: CRC value for the data block (used as a part of algorithm)
				@id [int]: identifier of the chunk to be encoded (used as a part of algorithm)
				@abShift [uint64_t]: asymmetric block shift value (key type based on decrypt bit)
	Returns:		output buffer of identical length as original
*/
static unsigned char *mincrypt_process(unsigned char *block, int size, int decrypt, uint32_t crc, int id, uint64_t *abShift)
{
	int i, shiftByte = 0;
	unsigned char *out = NULL;

	if (_iv == NULL) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		return NULL;
	}

	if ((type_approach == APPROACH_ASYMMETRIC) && (abShift == NULL)) {
		DPRINTF("%s: Asymmetric approach requires abShift pointer to be non-null\n", __FUNCTION__);
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

	if ((type_approach == APPROACH_ASYMMETRIC) && decrypt) {
		shiftByte = asymmetric_decrypt_u64((uint64_t)abShift, (uint64_t)_iva[id % _avector_size], (uint64_t)_ivn[id % _avector_size]);
	}
	else
	if ((type_approach == APPROACH_ASYMMETRIC) && !decrypt) {
		srand( time(NULL) + crc );
		shiftByte = (rand() + crc) % 256;
		DPRINTF("%s: Generated a new shift byte = %d\n", __FUNCTION__, shiftByte);

		*abShift = asymmetric_encrypt_u64(shiftByte, (uint64_t)_iva[id % _avector_size], (uint64_t)_ivn[id % _avector_size]);
	}

	for (i = 0; i < size; i++) {
		if ((type_approach == APPROACH_ASYMMETRIC) && decrypt)
			block[i] = shiftByte - block[i];

		out[i] = (_ival - crc - (_iv[i % _vector_size] << ((id * size) + i))) - block[i];

		if ((type_approach == APPROACH_ASYMMETRIC) && !decrypt)
			out[i] = shiftByte - out[i];
	}

	return out;
}

/*
	Function name:		mincrypt_encrypt
	Since version:		0.0.1
	Description:		Main function for the data encryption. Takes the block, size and id as input arguments with returning new size
	Arguments:		@block [buffer]: buffer of data to be encrypted/decrypted
				@size [int]: size of buffer
				@id [int]: identifier of the chunk to be encoded
				@new_size [size_t]: output integer value for the output buffer size
	Returns:		output buffer of new_size bytes
*/
DLLEXPORT unsigned char *mincrypt_encrypt(unsigned char *block, size_t size, int id, size_t *new_size)
{
	uint32_t crc = 0, abShift = 0;
	uint64_t abShift64 = 0;
	unsigned char *out = NULL, *tmp = NULL;
	unsigned char data[4] = { 0 };
	int csize = size;

	if ((_iv == NULL) ||(((_iva == NULL) || (_ivn == NULL)) && (type_approach == APPROACH_ASYMMETRIC))) {
		fprintf(stderr, "Error: Initialization vectors are not initialized\n");
		if (new_size != NULL)
			*new_size = -1;
		return NULL;
	}

	crc = crc32_block(block, size, 0xFFFFFFFF);
	DPRINTF("%s: Block CRC-32 value: 0x%"PRIx32"\n", __FUNCTION__, crc);

	tmp = mincrypt_process(block, size, 0, crc, id, &abShift64);
	if (tmp == NULL)
		return NULL;

	abShift = (uint32_t)abShift64;

	if (out_type == ENCODING_TYPE_BASE64) {
		int siglen = 0;
		int orig_size = (int) size;
		unsigned char *tmp2 = NULL;

		DPRINTF("%s: Original size is %d bytes\n", __FUNCTION__, orig_size);

		tmp2 = (unsigned char *)base64_encode( (const char *)tmp, &size);
		free(tmp);

		DPRINTF("%s: Encoded size is %ld bytes\n", __FUNCTION__, (unsigned long)size);

		siglen = strlen(SIGNATURE);
		csize = size + 17 + siglen;

                out = malloc( csize * sizeof(unsigned char) );
                memset(out, 0, csize);

		strncpy(out, SIGNATURE, siglen);
                out[siglen+0] = out_type;
                DPRINTF("%s: Saving out_type 0x%02x to chunk position 0\n", __FUNCTION__, out_type);
                UINT32STR(data, (uint32_t)orig_size);
                memcpy(out+siglen+1, data, 4);
                DPRINTF("%s: Saving original size (%d) to chunk positions 1 - 4 after signature = { %02x, %02x, %02x, %02x }\n",
                                __FUNCTION__, orig_size, out[1+siglen], out[2+siglen], out[3+siglen], out[4+siglen]);
                UINT32STR(data, (uint32_t)size);
                memcpy(out+siglen+5, data, 4);
                DPRINTF("%s: Saving new size (%ld) to chunk positions 5 - 8 after signature = { %02x, %02x, %02x, %02x }\n",
                                __FUNCTION__, (unsigned long)size, out[5+siglen], out[6+siglen], out[7+siglen], out[8+siglen]);
		UINT32STR(data, (uint32_t)crc);
		memcpy(out+siglen+9, data, 4);
		DPRINTF("%s: Saving CRC (0x%"PRIx32") to chunk positions 9 - 12 after signature = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, crc, out[9+siglen], out[10+siglen], out[11+siglen], out[12+siglen]);
		UINT32STR(data, (uint32_t)abShift);
                memcpy(out+siglen+13, data, 4);
		DPRINTF("%s: Saving abShift value (0x%"PRIx32") to chunk positions 13 - 16 after signature = { %02x, %02x, %02x, %02x}\n",
				__FUNCTION__, abShift, out[13+siglen], out[14+siglen], out[15+siglen], out[16+siglen]);
		memcpy(out+siglen+17, tmp2, size);

                free(tmp2);
	}
	else
	if (out_type == ENCODING_TYPE_BINARY) {
		int siglen = 0;

		siglen = strlen(SIGNATURE);
		csize = size + 17 + siglen;

		out = malloc( csize * sizeof(unsigned char) );
		memset(out, 0, csize);

		strncpy(out, SIGNATURE, siglen);
		out[siglen+0] = out_type;
		DPRINTF("%s: Saving out_type 0x%02x to chunk position 0\n", __FUNCTION__, out_type);
		UINT32STR(data, (uint32_t)size);
		memcpy(out+siglen+1, data, 4);
		DPRINTF("%s: Saving original size (%ld) to chunk positions 1 - 4 after signature = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, (unsigned long)size, out[1+siglen], out[2+siglen], out[3+siglen], out[4+siglen]);
		DPRINTF("%s: Leaving positions 5 to 8 after signature empty since they are reserved\n", __FUNCTION__);
		UINT32STR(data, (uint32_t)crc);
		memcpy(out+siglen+9, data, 4);
		DPRINTF("%s: Saving CRC (0x%"PRIx32") to chunk positions 9 - 12 after signature = { %02x, %02x, %02x, %02x }\n",
				__FUNCTION__, crc, out[9+siglen], out[10+siglen], out[11+siglen], out[12+siglen]);

		if (abShift > 0) {
			UINT32STR(data, (uint32_t)abShift);
			memcpy(out+siglen+13, data, 4);
			DPRINTF("%s: Saving abShift value (0x%"PRIx32") to chunk positions 13 - 16 after signature = { %02x, %02x, %02x, %02x}\n",
				__FUNCTION__, abShift, out[13+siglen], out[14+siglen], out[15+siglen], out[16+siglen]);
		}
		else {
			memset(data, 0, 4);
			memcpy(out+siglen+13, data, 4);
			DPRINTF("%s: Leaving positions 13 to 17 empty since they are reserved\n", __FUNCTION__);
		}

		DPRINTF("%s: Saving %ld bytes to the end of the stream\n", __FUNCTION__, (unsigned long)size);
		memcpy(out+siglen+17, tmp, size);

		free(tmp);
	}

	if (new_size != NULL) {
		DPRINTF("%s: New size is %"PRIi32"\n", __FUNCTION__, csize);
		*new_size = csize;
	}

	return out;
}

/*
	Function name:		mincrypt_decrypt
	Since version:		0.0.1
	Description:		Main function for the data decryption. Takes the block, size and id as input arguments with returning both decrypted encoded and decrypted decoded (raw) size
	Arguments:		@block [buffer]: buffer of data to be encrypted/decrypted
				@size [int]: size of buffer
				@id [int]: identifier of the chunk to be encoded
				@new_size [size_t]: output integer value for the output buffer size
				@read_size [int]: output integer value for the decoded output buffer size (different from new_size in case of base64 encoding)
	Returns:		output buffer of read_size bytes
*/
DLLEXPORT unsigned char *mincrypt_decrypt(unsigned char *block, size_t size, int id, size_t *new_size, int *read_size)
{
	unsigned char *signature = NULL;
	unsigned char data[4] = { 0 }, *out = NULL;
	uint32_t old_crc = 0, new_crc = 0;
	uint32_t csize = size;
	uint64_t abShift = 0;
	unsigned int enc_size = 0, orig_size = 0;
	int siglen = strlen(SIGNATURE);
	int i;

	if ((_iv == NULL) ||(((_iva == NULL) || (_ivn == NULL)) && (type_approach == APPROACH_ASYMMETRIC))) {
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

	signature = malloc( (siglen+1) * sizeof(char));
	memset(signature, 0, siglen+1);
	for (i = 0; i < siglen; i++)
		signature[i] = block[i];
	if (strcmp(signature, SIGNATURE) != 0) {
		fprintf(stderr, "Error: Block is not a valid mincrypt encrypted block (expected '%s' but '%s' found)\n",
			SIGNATURE, signature);
		free(signature);
		return NULL;
	}
	free(signature);

	DPRINTF("%s: Signature match. Going on...\n", __FUNCTION__);

	out_type = block[siglen+0];

	DPRINTF("%s: Found type 0x%02x [%s]\n", __FUNCTION__, out_type, (out_type == ENCODING_TYPE_BASE64) ? "base64" : "binary" );
	DPRINTF("%s: Input size is %ld\n", __FUNCTION__, (unsigned long)size);

	data[0] = block[siglen+1];
	data[1] = block[siglen+2];
	data[2] = block[siglen+3];
	data[3] = block[siglen+4];
	orig_size = GETUINT32(data);
	DPRINTF("%s: Original chunk size is %d bytes\n", __FUNCTION__, orig_size);

	data[0] = block[siglen+5];
	data[1] = block[siglen+6];
	data[2] = block[siglen+7];
	data[3] = block[siglen+8];
	enc_size = GETUINT32(data);
	DPRINTF("%s: Encoded chunk size is %ld bytes\n", __FUNCTION__, (unsigned long)size);

	data[0] = block[siglen+9];
	data[1] = block[siglen+10];
	data[2] = block[siglen+11];
	data[3] = block[siglen+12];
	old_crc = GETUINT32(data);
	DPRINTF("%s: Original CRC-32 value is 0x%"PRIx32"\n", __FUNCTION__, old_crc);

	data[0] = block[siglen+13];
	data[1] = block[siglen+14];
	data[2] = block[siglen+15];
	data[3] = block[siglen+16];
	abShift = (uint64_t)GETUINT32(data);
	if (abShift > 0)
		DPRINTF("%s: Asymmetric block shift value for decryption is 0x%"PRIx64"\n", __FUNCTION__, abShift);
	else
		DPRINTF("%s: No asymmetric block shift value set for decryption. Asymmetric approach not used\n", __FUNCTION__);

	if (out_type == ENCODING_TYPE_BINARY) {
		out = mincrypt_process(block+17+siglen, orig_size, 1, old_crc, id, abShift);
		if (out == NULL)
			return NULL;

		csize = orig_size;
	}
	else
	if (out_type == ENCODING_TYPE_BASE64) {
		unsigned char *tmp = NULL;

		tmp = (unsigned char *)base64_decode( (const char *)block+17+siglen, &size);
		tmp[ orig_size ] = 0;

		out = mincrypt_process(tmp, orig_size, 1, old_crc, id, abShift);
		if (out == NULL)
			return NULL;

		csize = orig_size;
	}

	DPRINTF("%s: Got chunk size of %d bytes\n", __FUNCTION__, csize);
	if (!simple_mode) {
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
	}
	else
		DPRINTF("Ignoring original CRC-32 value since simple mode is on\n");

	if (new_size != NULL) {
		DPRINTF("Setting new size to %d bytes\n", csize);
		*new_size = csize;
	}

	if (read_size != NULL)
		*read_size = (enc_size > 0) ? enc_size : csize;

	return out;
}

/*
	Function name:		mincrypt_encrypt_file
	Since version:		0.0.1
	Description:		Function for the entire file encryption. Takes the input and output files, salt, password and vector_multiplier value
	Arguments:		@filename1 [string]: input (original) file
				@filename2 [string]: output (encrypted) file
				@salt [string]: salt value to be used, may be NULL to use already set IVs if applicable, used only with conjuction password
				@password [string]: password value to be used, may be NULL to use already set IVs if applicable, used only with conjuction salt
				@vector_multiplier [int]: vector multiplier value, can be 0, used only if salt and password are set
	Returns:		0 for no error, otherwise error code
*/
DLLEXPORT int mincrypt_encrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier)
{
	unsigned char buf[BUFFER_SIZE] = { 0 };
	unsigned char *outbuf;
	int fd, fdOut, rc, id, ret = 0, errno_saved;

	if ((salt != NULL) && (password != NULL))
		mincrypt_set_password(salt, password, vector_multiplier);

	DPRINTF("%s: Encrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY
		#ifdef USE_LARGE_FILE
		 | O_LARGEFILE
		#endif
		#ifdef WINDOWS
		 | O_BINARY
		#endif
		);
	if (fd < 0) {
		errno_saved = errno;
		DPRINTF("%s: Cannot open file %s (code %d, %s)\n", __FUNCTION__, filename1, -errno, strerror(errno));
		return -errno_saved;
	}

	fdOut = open(filename2, O_WRONLY | O_TRUNC | O_CREAT
		#ifdef USE_LARGE_FILE
		 | O_LARGEFILE
		#endif
		#ifdef WINDOWS
		| O_BINARY
		#endif
		, 0644);
	if (fdOut < 0) {
		errno_saved = errno;
		DPRINTF("%s: Cannot open file %s for writing (code %d, %s)\n", __FUNCTION__, filename2, -errno, strerror(errno));
		return -errno_saved;
	}

	id = 1;
	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		size_t rct = (size_t)rc;
		outbuf = mincrypt_encrypt(buf, rct, id++, &rct);
		rc = (int)rct;
		write(fdOut, outbuf, rc);
		free(outbuf);
	}

	if (rc < 0)
		return -errno;

	close(fd);
	close(fdOut);

	DPRINTF("%s: Encryption done with code %d\n", __FUNCTION__, ret);
	return ret;
}

/*
	Function name:		mincrypt_decrypt_file
	Since version:		0.0.1
	Description:		Function for the entire file decryption. Takes the input and output files, salt, password and vector_multiplier value
	Arguments:		@filename1 [string]: input (encrypted) file
				@filename2 [string]: output (decrypted) file
				@salt [string]: salt value to be used, may be NULL to use already set IVs if applicable, used only with conjuction password
				@password [string]: password value to be used, may be NULL to use already set IVs if applicable, used only with conjuction salt
				@vector_multiplier [int]: vector multiplier value, can be 0, used only if salt and password are set
	Returns:		0 for no error, otherwise error code
*/
DLLEXPORT int mincrypt_decrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier)
{
	unsigned char buf[BUFFER_SIZE_BASE64+17+3 /* strlen(SIGNATURE) */] = { 0 };
	char *outbuf;
	int fd, fdOut, rc, rsize, id, ret = 0, to_read = BUFFER_SIZE_BASE64 + 17 + strlen(SIGNATURE);
	uint64_t already_read = 0, total = 0;

	if ((salt != NULL) && (password != NULL))
		mincrypt_set_password(salt, password, vector_multiplier);

	DPRINTF("%s: Decrypting %s to %s\n", __FUNCTION__, filename1, filename2);
	fd = open(filename1, O_RDONLY
		#ifdef USE_LARGE_FILE
		 | O_LARGEFILE
		#endif
		#ifdef WINDOWS
		 | O_BINARY
		#endif
		);
	if (fd < 0) {
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename1);
		return -EPERM;
	}
	fdOut = open(filename2, O_WRONLY | O_TRUNC | O_CREAT
		#ifdef USE_LARGE_FILE
		 | O_LARGEFILE
		#endif
                #ifdef WINDOWS
                 | O_BINARY
                #endif
		, 0644);
	if (fdOut < 0) {
		DPRINTF("%s: Cannot open file %s for writing\n", __FUNCTION__, filename2);
		return -EPERM;
	}

	id = 1;
	while ((rc = read(fd, buf, to_read)) > 0) {
		size_t rct = (size_t)rc;
		outbuf = mincrypt_decrypt(buf, rct, id++, &rct, &rsize);
		rc = (int)rct;
		already_read += rsize + 17 + strlen(SIGNATURE);
		if (simple_mode && (to_read != rsize + 17 + strlen(SIGNATURE))) {
			to_read = rsize + 17 + strlen(SIGNATURE);
			DPRINTF("%s: Current position is 0x%"PRIx64"\n", __FUNCTION__, already_read);
			if (lseek(fd, already_read, SEEK_SET) != already_read)
				DPRINTF("Warning: Seek error!\n");
		}
		else
		if (!simple_mode) {
			if (lseek(fd, already_read, SEEK_SET) != already_read)
				DPRINTF("Warning: Seek error!\n");
		}

		if (rc == -1) {
			DPRINTF("An error occured while decrypting input. Please check your salt/password and/or key if any used.\n");
			free(outbuf);
			close(fdOut);
			fdOut = -1;
			ret = -EINVAL;
			unlink(filename2);
			break;
		}

		write(fdOut, outbuf, rc);
		free(outbuf);

		total += rc;
	}

	if (fd != -1)
		close(fd);
	if (fdOut != -1)
		close(fdOut);

	if (total == 0) {
		ret = -EINVAL;
		unlink(filename2);
	}

	DPRINTF("%s: Decryption done with code %d\n", __FUNCTION__, ret);
	return ret;
}

