#!/bin/bash

php test-complex.phpt				|| exit 1
php test-asymmetric.phpt			|| exit 1
./test-binary.sh				|| exit 1
./test-asymmetric.sh				|| exit 1

echo "All tests passed successfully"
exit 0
