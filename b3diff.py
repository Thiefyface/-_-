#!/usr/bin/env python
import sys

def output(inp,color=None,lock=None):
    if not inp:
        return

    if color:
        sys.__stdout__.write("%s%s%s\n" % (color,str(inp),CLEAR))
        sys.__stdout__.flush()
    else:
        sys.__stdout__.write(str(inp)+"\n")
        sys.__stdout__.flush()

GREY='\033[1;30m'
RED,BOLDRED='\033[31m','\033[1;31m'
ORANGE,BOLDORANGE='\033[31m','\033[91;1m'
GREEN,BOLDGREEN='\033[92m','\033[92;1m'
LIME,BOLDLIME='\033[99m','\033[99;1m'
YELLOW,BOLDYELLOW='\033[93m','\033[93;1m'
BLUE,BOLDBLUE='\033[94m','\033[94;1m'
PURPLE,BOLDPURPLE='\033[95m','\033[95;1m'
CYAN,BOLDCYAN='\033[96m','\033[96;1m'
CLEAR='\033[00m'


def hexdump(src,length,perline,color,compress,outputres=True,digits=2,offset=0):
    result=[]
    dont_compress = False
    outputted_lines = False

    if length == 0 or src == "":
        return ""

    output_str = "%s%08" + "x  %-*s  %s"

    for i in range(0,length,perline):
        if compress and i > 0x60 and i < (length - perline):
            dont_compress = False

            try:
                for j in range(i,i+perline):
                    if src[j] != 0x0:
                        dont_compress = True
                        outputted_lines = False
                        break
            except:
                dont_compress = True
                outputted_lines = False

            if not dont_compress:
                if outputted_lines == False:
                    outputted_lines = True
                    if outputres:
                        output("-------------",CYAN)
                    else:
                        result.append("-------------")

                continue

        try:
            s=src[i:i+perline]
        except IndexError:
            s=src[i:]

        if not s:
            break

        hexa = ' '.join(["%0*x" %(digits,ord(x)) for x in s])
        while(len(hexa)) < (3*(perline-1)):
            hexa+=" "*3

        # add in that magical space
        if perline > 0x8:
            try:
                hexa = hexa[0:24] + " " + hexa[24:]
            except:
                pass

        text = ''.join([chr(x) if 0x20 <= x < 0x7f else '.' for x in s])

        result.append(output_str%(color,i+offset,(digits*2)+1,hexa, text))

        if outputres:
            output(output_str%(color,i+offset,(digits*2)+1,hexa, text))

    if len(result):
        return "\n".join(result)
    return ""


def main():

    if len(sys.argv) < 3:
        print("[x.x] Usage: %s <bin1> <bin2>"%sys.argv[0])
        return -1

    fd1 = None
    buf1 = ""
    fd2 = None
    buf2 = ""

    try:
        fd1 = open(sys.argv[1],"rb")
    except IOError:
        print("[x.x] Could not open %s!"%sys.argv[2])
        return -1 

    try:
        fd2 = open(sys.argv[2],"rb")
    except IOError:
        print("[x.x] Could not open %s!"%sys.argv[2])
        return -1 

    offset = 0
    break_flag = False 
    amt_per_iter = 10200004


    while not break_flag:
         
        buf1 = fd1.read(amt_per_iter)
        buf2 = fd2.read(amt_per_iter) 
        #print("%d, %d"%(len(buf1),len(buf2)))

        if not buf1 and buf2:
            output("[>_>] %s"%sys.argv[2],YELLOW)
            hexdump(buf2,amt_per_iter,16,CYAN,compress=True,outputres=True,digits=2,offset=offset)

            while buf2:
                hexdump(buf2,amt_per_iter,16,CYAN,compress=True,outputres=True,digits=2,offset=offset)
                offset += amt_per_iter 
                buf2 = fd2.read(amt_per_iter) 
            break

        if not buf2 and buf1:
            output("[<_<] %s"%sys.argv[1],YELLOW)
            hexdump(buf1,amt_per_iter,16,GREEN,compress=True,outputres=True,digits=2,offset=offset)
            while buf1:
                hexdump(buf1,amt_per_iter,16,GREEN,compress=True,outputres=True,digits=2,offset=offset)
                offset += amt_per_iter 
                buf1 = fd1.read(amt_per_iter)
            break
        
        if not buf2 and not buf1:
            break

        dump1 = hexdump(buf1,amt_per_iter,16,CLEAR,compress=False,outputres=False,digits=2,offset=offset).split("\n")
        dump2 = hexdump(buf1,amt_per_iter,16,CLEAR,compress=False,outputres=False,digits=2,offset=offset).split("\n")

        if len(dump2) > len(dump1):
            bigger = dump1
        else:
            bigger = dump2
    
        for i in range(0,len(bigger)):
            output("%s %s*** %s"%(dump1[i],PURPLE,dump2[i]))
            try:
                if dump1[i] != dump2[i]:
                    output("%s %s*** %s"%(dump1[i],PURPLE,dump2[i]))
                    break_flag = True 
            except IndexError:
                    if buf2 == bigger:
                        output("> %s"%(bigger[i]),CYAN)
                    else:
                        output("< %s"%(bigger[i]),GREEN)
                
                    break_flag = True 


        offset += amt_per_iter 
        #print("[>.>]) 0x%lx bytes read!"%offset)


if __name__ == "__main__":
    main()
