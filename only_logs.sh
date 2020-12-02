#!/bin/bash 
touch asan_buckets.txt
touch sigsegv_buckets.txt
touch other_buckets.txt
mkdir asan_dir  2>/dev/null
mkdir segv_dir  2>/dev/null
mkdir other_dir 2>/dev/null
mkdir dups      2>/dev/null

mkdir ../pocs/ 2>/dev/null
mkdir ../pocs/asan_dir 2>/dev/null
mkdir ../pocs/segv_dir 2>/dev/null
mkdir ../pocs/other_dir 2>/dev/null
mkdir ../pocs/dups 2>/dev/null

logcount=$(find . -name "crash-*.txt" | wc -l)

echo "[^_^] Processing $logcount logs"
sigseg=0
asan=0
other=0
dups=0

export IFS=$'\n'
for i in `find . -name "crash-*.txt"`; do
    # grep return 1 on fail...
    summary="$(grep "ERROR: AddressSanitizer" $i | cut -d " " -f 2- | sort -u)"
    if [ $? -eq 0 ]; then
        grep "$summary" asan_buckets.txt 
        if [ $? -eq 1 ]; then
            crash=$(basename `echo "$i"` | cut -d "." -f 1)
            echo $crash  >> asan_buckets.txt 
            echo $summary >> asan_buckets.txt 
            echo "--------------------------------" >> asan_buckets.txt
            asan=$(( asan + 1 ))
            mv $i asan_dir
            continue
        fi
    fi

    summary="$(grep -r "SIGSEGV" -A 5 $i | cut -d "." -f 2- | grep -v -- '--' | tr '\n' '|' )"
    if [ $? -eq 0 ]; then 
        grep "$summary" sigsegv_buckets.txt
        if [ $? -eq 1 ]; then
            crash=$(basename `echo "$i"` | cut -d "." -f 1)
            echo $crash >> sigsegv_buckets.txt 
            echo $summary >> sigsegv_buckets.txt 
            echo "--------------------------------" >> sigsegv_buckets.txt
            sigseg=$(( sigseg + 1 ))
            mv $i segv_dir
            mv ../$crash ../pocs/segv_dir
        fi
    fi
        
done

for i in `grep -L -e "SEGV" -e "ERROR: AddressSanitizer" crash-*.txt`; do
    crash=$(echo "$i" | cut -d "." -f 1) 
    echo $crash >> other_buckets.txt
    other=$(( other + 1 ))
    mv $i other_dir
    mv ../$crash ../pocs/other_dir
done

# anything left in this dir is a dup
for i in `ls | grep "^crash-.*txt$"`; do
    mv $i dups
    dups=$(( dups + 1 ))
    crash=$(basename `echo "$i"` | cut -d "." -f 1)
    mv ../$crash ../pocs/dups
done

echo "[>_>]*****Stats*******[<_<]" 
echo "[S_S] Sigsegv: $sigseg"
echo "[A_A] Asan   : $asan"
echo "[O.o] Other  : $other"
echo "[d.d] dups   : $dups"

