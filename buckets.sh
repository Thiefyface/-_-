#!/bin/bash

if [ -z $1 ]; then
    echo "[x.x] Usage:"
    echo "$0 <fuzz_binary> <fuzz_binary_options>" 
    exit
fi

mkdir crash_logs 2>/dev/null
export ASAN_OPTIONS=detect_leaks=0,allocator_may_return_null=1

for i in `find . -name "id*" | grep crashes`; do 
    if [ -f crash_logs/`basename $i`.txt ]; then
        echo "Old Entry: $i"
        continue
    else
        echo "New Entry: $i"
        gdb -ex run -ex quit --args $* $i 2>&1 | tee crash_logs/`basename $i`.txt 
        echo "*****************************" 
    fi
done

cd crash_logs
echo "" > asan_buckets.txt
echo "" > sigsegv_buckets.txt
echo "" > unknown_buckets.txt
echo "--------------------"
echo "--------------------"
echo "[^_^] Unique ASAN Crashes: "
export IFS=$'\n'
for i in `grep -r "ERROR: AddressSanitizer" *.txt | cut -d " " -f 2- | sort -u`; do 
    echo "$i\n"
    echo "$i\n" >> asan_buckets.txt
done 
echo

echo "[^_^] Unique SIGSEGV Crashes: "
for i in `grep -r "SIGSEGV" -A 2 *.txt | cut -d "." -f 2- | sort -u`; do 
    echo "$i\n"
    echo "$i\n" >> sigsegv_buckets.txt
done
echo 

echo "[^_^] Files with other types of crashes: "
for i in `grep -L -e "SIGSEGV" -e "ERROR: AddressSanitizer" *.txt`; do
    echo "$i\n" >> unkown_buckets.txt
done
echo  

echo "[^_^] Done with all"

