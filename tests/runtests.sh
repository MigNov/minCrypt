#!/bin/bash

php test-complex.phpt				|| exit 1
./test-binary.sh				|| exit 1
./test-fail.sh					|| exit 1

echo "All tests passed successfully"
exit 0
