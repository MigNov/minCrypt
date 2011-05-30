#!/bin/bash

MAX_FAIL_RELEVANCE=3

dd if=/dev/urandom of=test bs=1M count=64

# Valid password
../src/mincrypt --input-file=test --output-file=test.enc --salt=test --password=test > /dev/null
../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=test --password=test --decrypt --simple-mode > /dev/null
VALF=`../tools/bin/relevance -p SUCCESS test test.dec`
VAL=${VALF/.*}

if [ $VAL -lt 100 ]; then
	echo "Error: Success relevance is too small!"
	rm -f test test.enc test.dec
	exit 1
fi

# Invalid salt value
../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=tesu --password=test --decrypt --simple-mode > /dev/null
VALF=`../tools/bin/relevance -p FAIL_SALT test test.dec`
VAL=${VALF/.*}

if [ $VAL -gt $MAX_FAIL_RELEVANCE ]; then
	echo "Error: Failure relevance exceeds maximum allowed!"
	rm -f test test.enc test.dec
	exit 1
fi

# Invalid password value
../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=test --password=tesu --decrypt --simple-mode > /dev/null
VALF=`../tools/bin/relevance -p FAIL_PASSWORD test test.dec`
VAL=${VALF/.*}

if [ $VAL -gt $MAX_FAIL_RELEVANCE ]; then
	echo "Error: Failure relevance exceeds maximum allowed!"
	rm -f test test.enc test.dec
	exit 1
fi

rm -f test test.enc test.dec
echo "All relevance tests passed successfully"
