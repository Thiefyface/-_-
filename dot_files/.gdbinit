set disassembly-flavor intel
set follow-fork-mode parent
set pagination off
#source ~/gdb_stuff/gef/gef.py
#source ~/gdb_stuff/peda/peda.py 
#source ~/gdb_stuff/rr.txt

set prompt \033[1;95m<(^.^)>\033[1;92m#\033[0m
define boop
    nexti
    x/10i $pc
    end

define bl
    info break
    end

define rc 
    reverse-continue 
    context 
    end 
define rf 
    reverse-finish 
    context 
    end 
define rn 
    reverse-nexti 
    context 
    end 
define rnl 
    reverse-next 
    context 
    end 

define rs 
    reverse-stepi 
    context 
    end 

define rsl 
    reverse-step 
    context 
    end 
define r 
    context 
    end 
define n 
    nexti 
    end 
define s 
    stepi 
    end 

alias -a bp=break
