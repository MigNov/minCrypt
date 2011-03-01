#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_mincrypt.h"
#include "standard/info.h"

ZEND_DECLARE_MODULE_GLOBALS(mincrypt)

static function_entry mincrypt_functions[] = {
	PHP_FE(mincrypt_set_password,NULL)
	PHP_FE(mincrypt_set_output_type,NULL)
	PHP_FE(mincrypt_get_last_error, NULL)
	PHP_FE(mincrypt_reset_id, NULL)
	PHP_FE(mincrypt_last_size, NULL)
	PHP_FE(mincrypt_next_chunk_id, NULL)
	PHP_FE(mincrypt_encrypt, NULL)
	PHP_FE(mincrypt_decrypt, NULL)
	PHP_FE(mincrypt_encrypt_file, NULL)
	PHP_FE(mincrypt_decrypt_file, NULL)
	{NULL, NULL, NULL}
};


zend_module_entry mincrypt_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_MINCRYPT_WORLD_EXTNAME,
    mincrypt_functions,
    PHP_MINIT(mincrypt),
    PHP_MSHUTDOWN(mincrypt),
    PHP_RINIT(mincrypt),
    PHP_RSHUTDOWN(mincrypt),
    PHP_MINFO(mincrypt),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_MINCRYPT_WORLD_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MINCRYPT
ZEND_GET_MODULE(mincrypt)
#endif

PHP_RINIT_FUNCTION(mincrypt)
{
	MINCRYPT_G (last_error)=NULL;
	MINCRYPT_G (vector_set) = 0;
	MINCRYPT_G (last_size) = 0;
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(mincrypt)
{
	if (MINCRYPT_G (last_error)!=NULL) efree(MINCRYPT_G (last_error));
	return SUCCESS;
}

PHP_MINFO_FUNCTION(mincrypt)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Mincrypt support", "enabled");
	php_info_print_table_row(2, "Extension version", PHP_MINCRYPT_WORLD_VERSION);
	php_info_print_table_end();
}

PHP_MINIT_FUNCTION(mincrypt)
{
	REGISTER_LONG_CONSTANT("MINCRYPT_OUTPUT_TYPE_BINARY",	OUTPUT_TYPE_BINARY, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("MINCRYPT_OUTPUT_TYPE_BASE64",	OUTPUT_TYPE_BASE64, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(mincrypt)
{
	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

/* Function to set the error message and pass it to PHP */
void set_error(char *msg)
{
	php_error_docref(NULL TSRMLS_CC, E_WARNING,"%s",msg);
	if (MINCRYPT_G (last_error)!=NULL) efree(MINCRYPT_G (last_error));
	MINCRYPT_G (last_error)=estrndup(msg,strlen(msg));
}

static int next_id(int reset)
{
	if (reset)
		MINCRYPT_G (chunk_id) = 0;	

	return ++MINCRYPT_G (chunk_id);
}

PHP_FUNCTION(mincrypt_get_last_error)
{
	if (MINCRYPT_G (last_error) == NULL) RETURN_NULL();
	RETURN_STRING(MINCRYPT_G (last_error), 1);
}

PHP_FUNCTION(mincrypt_reset_id)
{
	RETURN_LONG( next_id(1) );
}

PHP_FUNCTION(mincrypt_next_chunk_id)
{
	RETURN_LONG( MINCRYPT_G (chunk_id) )
}

PHP_FUNCTION(mincrypt_last_size)
{
	RETURN_LONG( MINCRYPT_G (last_size) );
}

PHP_FUNCTION(mincrypt_set_password)
{
	char *salt, *pwd;
	int salt_len, pwd_len, vect_multiplier = 64;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l", &pwd,&pwd_len,&salt,&salt_len,&vect_multiplier) == FAILURE) {
        RETURN_FALSE;
	}

	if (vect_multiplier < 32) {
		set_error("Multiplier value is too small. Value must be higher than 32.");
		RETURN_FALSE;
	}
	
	crypt_set_password(salt, pwd, vect_multiplier);
	next_id(1);
	MINCRYPT_G (vector_set) = 1;
	
	RETURN_TRUE;
}

PHP_FUNCTION(mincrypt_set_output_type)
{
	int type = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &type) == FAILURE)
		RETURN_FALSE;

	MINCRYPT_G(type) = type;
	if (crypt_set_output_type(type) != 0) {
		set_error("Invalid type");
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(mincrypt_encrypt)
{
	unsigned char *block = NULL, *block_out = NULL;
	char *tmp = NULL;
	int block_len, block_size = -1;
	int rc;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &block,&block_len,&block_size) == FAILURE)
        	RETURN_FALSE;
	
	MINCRYPT_G (last_size) = 0;
	if (block_size <= 0)
		block_size = strlen( (char *)block );

	block_out = emalloc( (block_size + 16) * sizeof(unsigned char) );
	block_out = (unsigned char *)crypt_encrypt((unsigned char *)block, block_size + 1, next_id(0), &rc);
	if (rc <= 0) {
		efree(block_out);
		set_error("Internal error!");
		RETURN_FALSE;
	}

	tmp = (char *)base64_encode( (const char *)block_out, &rc );

	MINCRYPT_G (last_size) = rc;

	RETURN_STRING(tmp, 1);
}

PHP_FUNCTION(mincrypt_decrypt)
{
	unsigned char *block, *block_out = NULL;
	char *tmp = NULL;
	int block_len, block_size = -1;
	int rc;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &block,&block_len,&block_size) == FAILURE)
	        RETURN_FALSE;
	
	MINCRYPT_G (last_size) = 0;
	if (block_size < 0)
		block_size = strlen( (char *)block );

	rc = block_size;
	tmp = (char *)base64_decode( (const char *)block, &rc );

	block_out = emalloc( (block_size + 16) * sizeof(unsigned char) );
	block_out = (unsigned char *)crypt_decrypt((unsigned char *)tmp, rc - 1, next_id(0), &rc, NULL);

	if (rc < 0) {
		efree(block_out);
		set_error("Decryption failed!");
		RETURN_FALSE;
	}
	
	block_out[rc] = 0;
	
	MINCRYPT_G (last_size) = rc;

	RETURN_STRING((char *)block_out, 1);
}

PHP_FUNCTION(mincrypt_encrypt_file)
{
	char *file1, *file2;
	int file1_len, file2_len, rc;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &file1,&file1_len,&file2,&file2_len) == FAILURE) {
        RETURN_FALSE;
	}
	
	rc = crypt_encrypt_file(file1, file2, NULL, NULL, 0);
	switch (rc) {
		case -EPERM: set_error("Cannot access file");
					 break;
		case -EIO:   set_error("Cannot write file");
					 break;
		case -EINVAL:set_error("Decryption failed");
					 break;
	}

	RETURN_LONG( rc );
}

PHP_FUNCTION(mincrypt_decrypt_file)
{
	char *file1, *file2;
	int file1_len, file2_len, rc;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &file1,&file1_len,&file2,&file2_len) == FAILURE) {
        RETURN_FALSE;
	}
	
	rc = crypt_decrypt_file(file1, file2, NULL, NULL, 0);
	switch (rc) {
		case -EPERM: set_error("Cannot access file");
					 break;
		case -EIO:   set_error("Cannot write file");
					 break;
		case -EINVAL:set_error("Decryption failed");
					 break;
	}
	
	RETURN_LONG( rc );
}

