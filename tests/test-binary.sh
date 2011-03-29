#!/bin/bash

maxiter=2
iter=0
X=0

dd if=/dev/zero of=test bs=1M count=256

while [ $iter -lt $maxiter ]; do
  T1=`date +%s`
  ../src/mincrypt --input-file=test --output-file=test.enc --salt=test --password=test
  T2=`date +%s`
  ../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=test --password=test --decrypt --simple-mode
  T3=`date +%s`
  let X1=$T2-$T1
  let X2=$T3-$T1
  let iter=$iter+1
  echo "Encrypt duration for iteration #$iter: $X1 seconds"
  echo "Decrypt duration for iteration #$iter: $X2 seconds"
  let total=$total+$X1+$X2
done

rm -f test test.enc test.dec

echo "Total: $total seconds"
let AVG=$total/$iter
echo "Average time per one iteration: $AVG seconds (for both encryption and decryption)"
