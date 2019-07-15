#!/usr/bin/env python
import sys
import gzip

def main():
    if len(sys.argv) < 2:
        print "[x.x] Usage: %s <file w/gunzip buffer somewhere>"    
        sys.exit()

    buf = ""
    with open(sys.argv[1],"rb") as f:
        buf = f.read()

    for i in range(len(buf),0,-1):
    #for i in range(0,len(buf)):
        with open('test.gz','wb') as f:
            f.write(buf)
        try:
            with gzip.open('test.gz','rb') as f:
                with open('text','wb') as e:
                    e.write(f.read())
            break
        except Exception as e:
            print e 
            pass

    print "[^-^] Found a gunzip at %d" % i
    print "Wrote to test.gz"
     

if __name__ == "__main__":
    main()
