/*
 *  asymmetric.c: asymmetric operations
 *
 *  Copyright (c) 2010-2011, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#define DEBUG_ASYMMETRIC

// Asymmetrics should not be disabled except debugging purposes
//#define DISABLE_ASYMMETRIC

#include "mincrypt.h"

#ifdef DEBUG_ASYMMETRIC
#define DPRINTF(fmt, args...) \
do { fprintf(stderr, "[mincrypt/asymmetric] " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

int get_random_values(uint64_t seed, int size, uint64_t p, uint64_t q, uint64_t *oe, uint64_t *od, uint64_t *on, int flags)
{
	long modtime = (long)time(NULL);
	uint64_t d, e, n, i, eu, xp, xq, xseed;

	DPRINTF("%s: p = %"PRIu64", q = %"PRIu64"\n", __FUNCTION__, p, q);

	DPRINTF("%s: mod time = %ld, size = %d\n", __FUNCTION__, modtime, size);

	xp = (uint64_t)((p / (uint64_t)modtime) % (uint64_t)size);
	xq = (q / (uint64_t)modtime) % (uint64_t)size;

	xp = find_nearest_prime_number(xp, flags);
	if (xp == (uint64_t)-1) {
		DPRINTF("%s: Invalid prime number for p\n", __FUNCTION__);
		return -EINVAL;
	}

	xq = find_nearest_prime_number(xq, flags);
	if (xq == (uint64_t)-1) {
		DPRINTF("%s: Invalid prime number for q\n", __FUNCTION__);
		return -EINVAL;
	}

	if (xp < 7)
		xp = find_nearest_prime_number( xp + 7, GET_NEAREST_BIGGER );

	if (xq < 7)
		xq = find_nearest_prime_number( xq + 7, GET_NEAREST_BIGGER );

	DPRINTF("%s: x/p = %"PRIu64", x/q = %"PRIu64"\n", __FUNCTION__, xp, xq);

	n = xp * xq;
	eu = (xp - 1) * (xq - 1);

	DPRINTF("%s: n = %"PRIu64", eu = %"PRIu64"\n", __FUNCTION__, n, eu);

	d = 0;
	xseed = (seed == 0) ? time(NULL) : seed % time(NULL);

	srand( xseed );
	e = find_nearest_prime_number( rand() % eu, flags );
	if (e == (uint64_t)-1) {
		DPRINTF("%s: Invalid prime number for e\n", __FUNCTION__);
		return -EINVAL;
	}

	for (i = 0; i < (int)n; i++) {
		if ((i * (int)e) % eu == 1.) {
			d = i;
			break;
		}
	}

	DPRINTF("%s: seed = %"PRIu64", d = %"PRIu64", e = %"PRIu64"\n", __FUNCTION__, xseed, d, e);
	DPRINTF("%s: int seed = %d, int d = %d, int e = %d\n", __FUNCTION__, (int)xseed, (int)d, (int)e);

	if (oe != NULL)
		*oe = e;
	if (od != NULL)
		*od = d;
	if (on != NULL)
		*on = n;

	return 0;
}

int check_is_prime_number_since(uint64_t start, uint64_t number)
{
	int i = 0;
	uint64_t tmp;

	if (number <= 0)
		return -1;

	/* Even number cannot be prime */
	if (number % 2 == 0)
		return 0;

	for (tmp = start; tmp < number; tmp += 2) {
		/* If we've passed square root then it must be prime number */
		if ((uint64_t)pow(tmp, 2) > number)
			break;

		if (number % tmp == 0) {
			i++;
			break;
		}
	}

	return (i == 0);
}

int check_is_prime_number(uint64_t number)
{
	return check_is_prime_number_since(3, number);
}

tPrimes generate_primes_in_range(uint64_t start, uint64_t end)
{
	int num = 0;
	uint64_t i;
	uint64_t *primes = NULL;
	tPrimes oprimes;

	primes = (uint64_t *)malloc( 1 * sizeof(uint64_t) );
	for (i = start; i <= end; i++) {
		if (check_is_prime_number(i)) {
			primes = (uint64_t *) realloc( primes, (num+1) * sizeof(uint64_t) );
			primes[num] = i;
			num++;
			DPRINTF("%s: Number %" PRIi64" is a prime number\n", __FUNCTION__, i);
		}
	}

	oprimes.num = num;
	oprimes.start = start;
	oprimes.end = end;
	oprimes.numbers = malloc( (num+1) * sizeof(uint64_t) );
	memcpy(oprimes.numbers, primes, num * sizeof(uint64_t));
	free(primes);

	return oprimes;
}

tPrimes generate_primes_in_bit_range(int start, int end)
{
	uint64_t n_start;
	uint64_t n_end;

	if ((start < 0) || (start > 63) || (end < 0) || (end > 63))
		return (tPrimes) {0};

	n_start = pow(2, start);
	n_end = pow(2, end);

	DPRINTF("%s(%d, %d) Generated n_start of %"PRIi64" and n_end of %"PRIi64"\n", __FUNCTION__,
		start, end, n_start, n_end);

	return generate_primes_in_range(n_start, n_end);
}

uint64_t find_nearest_prime_number(uint64_t number, int flags)
{
	uint64_t i;

	if (flags == GET_NEAREST_BIGGER) {
		for (i = number; i < (uint64_t)-1; i++) {
			if (check_is_prime_number(i))
				return i;
		}

		DPRINTF("%s: Cannot get higher prime number than %"PRIu64"\n", __FUNCTION__, number);
	}
	else
	if (flags == GET_NEAREST_SMALLER) {
		for (i = number; i > 0; i--) {
			if (check_is_prime_number(i))
				return i;
		}

		DPRINTF("%s: Cannot get smaller prime number than %"PRIu64"\n", __FUNCTION__, number);
	}
	else
		DPRINTF("%s: Invalid flag for number %"PRIu64": %d\n", __FUNCTION__, number, flags);

	return (uint64_t)-1;
}

tPrimes get_prime_elements(uint64_t number)
{
	int i;
	int num_primes = 0;
	char a[2] = { 0 };
	char tmp[128] = { 0 };
	char tmp2[128] = { 0 };
	uint64_t *primes = NULL;
	tPrimes oprimes;

	snprintf(tmp, sizeof(tmp), "%"PRIi64, number);
	primes = (uint64_t *)malloc( 1 * sizeof(uint64_t) );
	for (i = 0; i < strlen(tmp); i++) {
		a[0] = tmp[i];
		strcat(tmp2, a);

		if (check_is_prime_number(atoll(tmp2))) {
			primes = (uint64_t *) realloc( primes, (num_primes+1) * sizeof(uint64_t) );
			primes[num_primes] = atoll(tmp2);
			num_primes++;
		}
	}

	oprimes.num = num_primes;
	oprimes.start = 0;
	oprimes.end = 0;
	oprimes.numbers = malloc( (num_primes+1) * sizeof(uint64_t) );
	memcpy(oprimes.numbers, primes, num_primes * sizeof(uint64_t));
	free(primes);

	return oprimes;
}

void free_primes(tPrimes p)
{
	free(p.numbers);
}

unsigned int asymmetric_encrypt(unsigned int c, int e, int n)
{
	#ifdef DISABLE_ASYMMETRIC
	return c;
	#endif
	return (unsigned int)pow_and_mod((uint64_t)c, (uint64_t)e, (uint64_t)n);
}

unsigned int asymmetric_decrypt(unsigned int c, int d, int n)
{
	#ifdef DISABLE_ASYMMETRIC
	return c;
	#endif
	return (unsigned int)pow_and_mod((uint64_t)c, (uint64_t)d, (uint64_t)n);
}

uint64_t asymmetric_encrypt_u64(uint64_t c, uint64_t e, uint64_t n)
{
	#ifdef DISABLE_ASYMMETRIC
	return c;
	#endif

	uint64_t ret;
	ret = pow_and_mod(c, e, n);
	DPRINTF("%s: c = %8"PRIi64", d = %8"PRIi64", n = %8"PRIi64" returning %"PRIi64"\n", __FUNCTION__, c, e, n, ret);
	return ret;
}

uint64_t asymmetric_decrypt_u64(uint64_t c, uint64_t d, uint64_t n)
{
	#ifdef DISABLE_ASYMMETRIC
	return c;
	#endif

	uint64_t ret;
	ret = pow_and_mod(c, d, n);
	DPRINTF("%s: c = %8"PRIi64", d = %8"PRIi64", n = %8"PRIi64" returning %"PRIi64"\n", __FUNCTION__, c, d, n, ret);
	return ret;
	
}

