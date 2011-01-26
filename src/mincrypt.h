#ifndef MINCRYPT_H
#define MINCRYPT_H

#define BUFFER_SIZE			(1 << 17)       /* Make 128 kB to be default buffer size */
#define O_LARGEFILE			0x0200000
#define SIGNATURE			"CAF"
#define DEFAULT_SALT_VAL		SIGNATURE
#define DEFAULT_VECTOR_MULT		0x20

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <lzma.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdlib.h>
#include <math.h>

#define UINT32STR(var, val)	\
	var[0] = (val >> 24) & 0xff;	\
	var[1] = (val >> 16) & 0xff;	\
	var[2] = (val >>  8) & 0xff;	\
	var[3] = (val      ) & 0xff;

#define UINT64STR(var, val)	\
	var[0] = (val >> 56) & 0xff;	\
	var[1] = (val >> 48) & 0xff;	\
	var[2] = (val >> 40) & 0xff;	\
	var[3] = (val >> 32) & 0xff;	\
	var[4] = (val >> 24) & 0xff;	\
	var[5] = (val >> 16) & 0xff;	\
	var[6] = (val >>  8) & 0xff;	\
	var[7] = (val      ) & 0xff;
#define BYTESTR(var, val)	\
	var[0] =  val;

#define WORDSTR(var, val)	\
	var[0] = (val >> 8) & 0xff;	\
	var[1] = (val     ) & 0xff;

#define GETBYTE(var)    (var[0])
#define GETWORD(var)    ((var[0] << 8) + (var[1]))
#define GETUINT32(var)	((var[0] << 24) + (var[1] << 16) + (var[2] << 8) + (var[3]))
#define GETUINT64(var)	(((uint64_t)var[0] << 56) + ((uint64_t)var[1] << 48) + ((uint64_t)var[2] << 40) + \
			((uint64_t)var[3] << 32) + ((uint64_t)var[4] << 24) + ((uint64_t)var[5] << 16)  + \
			((uint64_t)var[6] << 8) + (uint64_t)var[7])

#endif
