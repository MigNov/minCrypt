#!/bin/bash

SIZEMB=256
maxiter=5
iter=0
iter2=0
X=0
SALT='test'
PASSWORD='test'
BADPWD='tesu'
total_good=0
total_bad=0

dd if=/dev/urandom of=test bs=1M count=$SIZEMB

while [ $iter -lt $maxiter ]; do
  [ `id -u` == 0 ] && echo 3 > /proc/sys/vm/drop_caches
  T1=`date +%s`
  ../src/mincrypt --input-file=test --output-file=test.enc --salt=$SALT --password=$PASSWORD
  T2=`date +%s`
  ../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=$SALT --password=$PASSWORD --decrypt --simple-mode
  T3=`date +%s`
  let X1=$T2-$T1
  let X2=$T3-$T1
  let iter=$iter+1
  echo "Encrypt duration for iteration #$iter: $X1 seconds"
  echo "Valid decrypt duration for iteration #$iter: $X2 seconds"
  let total_good=$total_good+$X1+$X2
done

while [ $iter2 -lt $maxiter ]; do
  [ `id -u` == 0 ] && echo 3 > /proc/sys/vm/drop_caches
  T1=`date +%s`
  ../src/mincrypt --input-file=test.enc --output-file=test.dec --salt=$SALT --password=$BADPWD --decrypt
  T2=`date +%s`
  let X1=$T2-$T1
  let iter2=$iter2+1
  echo "Invalid decrypt duration for iteration #$iter2: $X1 seconds"
  let total_bad=$total_bad+$X1+$X2
done

rm -f test test.enc test.dec

let total=$total_bad+$total_good

let AVG=$total_good/$iter
echo "Average time per one good iteration: $AVG seconds (for both encryption and decryption)"
let AVG=$total_bad/$iter2
echo "Average time per one bad iteration: $AVG seconds (for both encryption and decryption)"
echo "Total: $total seconds"
