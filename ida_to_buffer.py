#!/usr/bin/env python2
import sys

def main():
    inpbuf = ""

    with open(sys.argv[1],"rb") as f:
        inpbuf = f.read() 

    outbuf = "" 
    for line in inpbuf.split("\n"):
        _tmp = line.split(";")
        if len(_tmp) == 1:
            delim = line.find("db") 
            if delim == -1:
                continue
            outbuf+="\\x%02x"%int(_tmp[0][delim+2:].replace("h",""),16)
            continue
        
        if _tmp[0][-2:] == "h ":
            outbuf+="\\x" + _tmp[0][-4:-2]
        elif "XREF" in _tmp[1]:
            delim = _tmp[0].find("db") 
            if delim == -1:
                continue
            outbuf+="\\x%02x"%int(_tmp[0][delim+2:].replace("h",""),16)
        
    print outbuf


if __name__ == "__main__":
    main()
