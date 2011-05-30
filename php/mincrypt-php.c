/*
 *  mincrypt-php.c: PHP bindings for Minimalistic encryption system (minCrypt)
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

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
	PHP_FE(mincrypt_set_encoding_type,NULL)
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
	REGISTER_LONG_CONSTANT("MINCRYPT_ENCODING_TYPE_BINARY",	ENCODING_TYPE_BINARY, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("MINCRYPT_ENCODING_TYPE_BASE64",	ENCODING_TYPE_BASE64, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(mincrypt)
{
	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

/* Function to set the error message and pass it to PHP */
/*
	Private function name:	set_error
	Since version:		0.0.1
	Description:		Function to set the error message from the library
	Arguments:		@msg [string]: error message string
	Returns:		None
*/
void set_error(char *msg)
{
	php_error_docref(NULL TSRMLS_CC, E_WARNING,"%s",msg);
	if (MINCRYPT_G (last_error)!=NULL) efree(MINCRYPT_G (last_error));
	MINCRYPT_G (last_error)=estrndup(msg,strlen(msg));
}

/*
	Private function name:	next_id
	Since version:		0.0.1
	Description:		Function to get the next chunk id, can be reset to 0 before processing to start over
	Arguments:		@reset [int]: flag to reset the chunk id counter or not, can be 0 (don't reset) or 1 (reset)
	Returns:		id of new chunk
*/
static int next_id(int reset)
{
	if (reset)
		MINCRYPT_G (chunk_id) = 0;	

	return ++MINCRYPT_G (chunk_id);
}

/*
	Function name:		mincrypt_get_last_error
	Since version:		0.0.1
	Description:		Function to get the last error set by set_error() function
	Arguments:		None
	Returns:		last error string or NULL value if no error yet
*/
PHP_FUNCTION(mincrypt_get_last_error)
{
	if (MINCRYPT_G (last_error) == NULL) RETURN_NULL();
	RETURN_STRING(MINCRYPT_G (last_error), 1);
}

/*
	Function name:		mincrypt_reset_id
	Since version:		0.0.1
	Description:		Function to reset the chunk id for using the low-level API in PHP
	Arguments:		None
	Returns:		1 as id of the new chunk since it's always starting at 1
*/
PHP_FUNCTION(mincrypt_reset_id)
{
	RETURN_LONG( next_id(1) );
}

/*
	Function name:		mincrypt_next_chunk_id
	Since version:		0.0.1
	Description:		Function to get the next chunk id
	Arguments:		None
	Returns:		id of next chunk
*/
PHP_FUNCTION(mincrypt_next_chunk_id)
{
	RETURN_LONG( MINCRYPT_G (chunk_id) )
}

/*
	Function name:		mincrypt_last_size
	Since version:		0.0.1
	Description:		Function to get output size of last encrypt/decrypt operation
	Arguments:		None
	Returns:		size long value
*/
PHP_FUNCTION(mincrypt_last_size)
{
	RETURN_LONG( MINCRYPT_G (last_size) );
}

/*
	Function name:		mincrypt_set_password
	Since version:		0.0.1
	Description:		Function to set the password and generate initialization vectors. Function also sets the next_id to 1 (resets it).
	Arguments:		@password [string]: password for IV generation
				@salt [string]: salt value for IV generation
				@vector_multiplier [int]: vector multiplier value for IV generation
	Returns:		TRUE if success, FALSE if error. You can get the error using mincrypt_get_last_error() call
*/
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

/*
	Function name:		mincrypt_set_encoding_type
	Since version:		0.0.1
	Description:		Function to set the output type for encryption. Applies only to the encryption and decryption itself as data are always returned to PHP script as base64.
	Arguments:		@type [int]: type identified, only MINCRYPT_ENCODING_TYPE_BINARY are MINCRYPT_ENCODING_TYPE_BASE64 are supported right now
	Returns:		TRUE if success, FALSE if error. You can get the error using mincrypt_get_last_error() call
*/
PHP_FUNCTION(mincrypt_set_encoding_type)
{
	int type = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &type) == FAILURE)
		RETURN_FALSE;

	MINCRYPT_G(type) = type;
	if (crypt_set_encoding_type(type) != 0) {
		set_error("Invalid type");
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

/*
	Function name:		mincrypt_encrypt
	Since version:		0.0.1
	Description:		Function for the low-level data block encryption
	Arguments:		@block [buffer]: input buffer for the data block encryption
				@block_size [int]: size of the input buffer
				@flags [int]: flags for decryption, can be MINCRYPT_ENCODING_TYPE_BINARY or MINCRYPT_ENCODING_TYPE_BASE64 meaning the output is in this format
	Returns:		encrypted data, FALSE if error. You can get the error using mincrypt_get_last_error() call
*/
PHP_FUNCTION(mincrypt_encrypt)
{
	unsigned char *block = NULL, *block_out = NULL;
	char *tmp = NULL;
	int block_len, block_size = -1;
	size_t rc;
	int flags = 0;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|l", &block,&block_len,&block_size,&flags) == FAILURE)
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

	if (flags & ENCODING_TYPE_BASE64) {
		tmp = (char *)base64_encode( (const char *)block_out, &rc);
		MINCRYPT_G (last_size) = rc;
		RETURN_STRING(tmp, 1);
	}
	else {
		tmp = (char *)emalloc( rc * sizeof(unsigned char) );
		memcpy(tmp, block_out, rc);
		MINCRYPT_G (last_size) = rc;

		Z_STRLEN_P(return_value) = rc;
		Z_STRVAL_P(return_value) = tmp;
		Z_TYPE_P(return_value) = IS_STRING;
	}
}

/*
	Function name:			mincrypt_decrypt
	Since version:			0.0.1
	Description:			Function for the low-level data block decryption
	Arguments:			@block [buffer]: input buffer for the data block decryption
					@block_size [int]: size of the input buffer
					@flags [int]: flags for decryption, can be MINCRYPT_ENCODING_TYPE_BINARY or MINCRYPT_ENCODING_TYPE_BASE64 meaning the input is in this format
	Returns:			decrypted data, FALSE if error. You can get the error using mincrypt_get_last_error() call
*/
PHP_FUNCTION(mincrypt_decrypt)
{
	unsigned char *block, *block_out = NULL;
	char *tmp = NULL;
	int block_len, block_size = -1;
	size_t rc;
	int flags = 0;
	
	if (!MINCRYPT_G (vector_set)) {
		set_error("Initialization vectors are not set. Please set them first!");
		RETURN_FALSE;
	}
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|l", &block,&block_len,&block_size,&flags) == FAILURE)
	        RETURN_FALSE;
	
	MINCRYPT_G (last_size) = 0;
	if (block_size < 0)
		block_size = strlen( (char *)block );

	rc = block_size;
	if (flags & ENCODING_TYPE_BASE64)
		tmp = (char *)base64_decode( (const char *)block, &rc );

	block_out = emalloc( (block_size + 16) * sizeof(unsigned char) );
	if (block_out == NULL) {
		efree(block_out);
		set_error("Cannot allocate decryption buffer");
		RETURN_FALSE;
	}

	if (flags & ENCODING_TYPE_BASE64)
		block_out = (unsigned char *)crypt_decrypt((unsigned char *)tmp, rc - 1, next_id(0), &rc, NULL);
	else {
		block_out = (unsigned char *)crypt_decrypt((unsigned char *)block, block_size - 1, next_id(0), &rc, NULL);
		rc--;
	}

	if ((block_out == NULL) || (rc < 0)) {
		efree(block_out);
		set_error("Decryption failed!");
		RETURN_FALSE;
	}

	free(tmp);
	tmp = (char *)emalloc( rc * sizeof(unsigned char) );
	memcpy(tmp, block_out, rc);
	
	MINCRYPT_G (last_size) = rc;

	Z_STRLEN_P(return_value) = rc;
	Z_STRVAL_P(return_value) = tmp;
	Z_TYPE_P(return_value) = IS_STRING;
}

/*
	Function name:			mincrypt_encrypt_file
	Since version:			0.0.1
	Description:			Function for high-level encryption of the whole file. You have to have the IVs set using mincrypt_set_password() call already
	Arguments:				@file1 [string]: input (original) file
	Returns:				0 for no error or error code. mincrypt_get_last_error() could be used to get the error string representation if not 0
*/
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

/*
	Function name:			mincrypt_decrypt_file
	Since version:			0.0.1
	Description:			Function for high-level decryption of the whole file. You have to have the IVs set using mincrypt_set_password() call already
	Arguments:				@file1 [string]: input (encrypted) file
							@file2 [string]: output (decrypted) file
	Returns:				0 for no error or error code. mincrypt_get_last_error() could be used to get the error string representation if not 0
*/
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

