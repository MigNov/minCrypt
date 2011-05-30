/*
 *  php_mincrypt.h: PHP bindings header file
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#ifndef PHP_MINCRYPT_H
#define PHP_MINCRYPT_H 1

#ifdef ZTS
#include "TSRM.h"
#endif

#include "../src/mincrypt.h"

ZEND_BEGIN_MODULE_GLOBALS(mincrypt)
	int chunk_id;
	int vector_set;
	int type;
	long last_size;
	char *last_error;
ZEND_END_MODULE_GLOBALS(mincrypt)

#ifdef ZTS
#define MINCRYPT_G(v) TSRMG(mincrypt_globals_id, zend_mincrypt_globals *, v)
#else
#define MINCRYPT_G(v) (mincrypt_globals.v)
#endif

#define PHP_MINCRYPT_WORLD_VERSION "0.0.1a"
#define PHP_MINCRYPT_WORLD_EXTNAME "mincrypt"

PHP_MINIT_FUNCTION(mincrypt);
PHP_MSHUTDOWN_FUNCTION(mincrypt);
PHP_RINIT_FUNCTION(mincrypt);
PHP_RSHUTDOWN_FUNCTION(mincrypt);
PHP_MINFO_FUNCTION(mincrypt);

PHP_FUNCTION(mincrypt_set_password);
PHP_FUNCTION(mincrypt_set_encoding_type);
PHP_FUNCTION(mincrypt_get_last_error);
PHP_FUNCTION(mincrypt_reset_id);
PHP_FUNCTION(mincrypt_last_size);
PHP_FUNCTION(mincrypt_next_chunk_id);
PHP_FUNCTION(mincrypt_encrypt);
PHP_FUNCTION(mincrypt_decrypt);
PHP_FUNCTION(mincrypt_encrypt_file);
PHP_FUNCTION(mincrypt_decrypt_file);

extern zend_module_entry mincrypt_module_entry;
#define phpext_mincrypt_ptr &mincrypt_module_entry

#endif
