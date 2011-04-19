#ifndef MINCRYPT_H
#define MINCRYPT_H

#ifdef __cplusplus
extern "C"
{
#endif

unsigned char *base64_encode(const char *in, size_t *size);
unsigned char *base64_decode(const char *in, size_t *size);
void crypt_set_password(char *salt, char *password, int vector_multiplier);
int crypt_set_output_type(int type);
void crypt_cleanup();
unsigned char *crypt_encrypt(unsigned char *block, int size, int id, size_t *new_size);
unsigned char *crypt_decrypt(unsigned char *block, int size, int id, size_t *new_size, int *read_size);
int crypt_encrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier);
int crypt_decrypt_file(char *filename1, char *filename2, char *salt, char *password, int vector_multiplier);

int vect_mult = -1;

#ifdef __cplusplus
}
#endif

#endif
