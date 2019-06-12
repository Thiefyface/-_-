#!/bin/bash

if [ -z $1 ]; then
    echo "[x.x] Usage:"
    echo "$0 <fuzz_binary> <fuzz_binary_options>" 
    exit
fi

mkdir crash_logs

for i in `find . -name "id*" | grep crashes`; do 
    gdb -ex run -ex quit --args $* $i 2>&1 | tee crash_logs/`basename $i`.txt 
done

cd crash_logs
echo "--------------------"
echo "--------------------"
echo "--------------------"
echo "--------------------"
echo "[^_^] Unique Crashes: "
grep -r "ERROR: AddressSanitizer" *.txt | cut -d " " -f 2- | sort -u >> bucket_results.txt
grep -r "SIGSEGV" -A 2 *.txt | cut -d "." -f 2 | sort -u >> bucket_results.txt
