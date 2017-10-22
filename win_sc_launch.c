#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void run_shellcode(int argc, char* argv[]){
    int (*shellcode)();
    FILE *sc_file;

    if (argc < 2){
        printf("[>_>] Needs more args yo\n");
        return;
    }

    sc_file = fopen(argv[1],"rb");

    if (sc_file == NULL){
        printf("[x.x] Could not open %s, exit\n",argv[1]);
        return;
    }

    fseek(sc_file,0,SEEK_END);
    size_t sc_size = ftell(sc_file);
    fseek(sc_file,0,SEEK_SET);
    printf("[^_^] Size of shellcode:0x%x\n",sc_size);

    //void * sc_buff = (void *)malloc(sc_size);
    // VirtualAlloc(dst,size,type(commit/reserve),perms)
    void * sc_buff = VirtualAlloc(0x0,sc_size,0x3000,0x40);
    printf("allocated 0x%x buff @ 0x%x\n",(unsigned int)sc_buff,sc_size);
    fread(sc_buff,sc_size,1,sc_file);
    //fclose(sc_file);

    shellcode = (int (*)()) sc_buff;
    printf("[!_!] Launching!\n");
    (int) (*shellcode)();

}
