#include <stdio.h>
#include "debug.h"

void help() {
    ACT("./elfinject <victim> <shellcode.bin> <outfile>");
    exit(1);
}

void work(char *victim, char *shcd, char *outfile) {
    
}


int main(int argc, char** argv)
{
    char *victim  = NULL;
    char *shcd    = NULL;
    char *outfile = NULL;

    if(argc != 4) {
        goto help;
    }

    victim  = argv[1];
    shcd    = argv[2];
    outfile = argv[3];

    if( victim == NULL || shcd == NULL || outfile == NULL) goto help;

    work(victim, shcd, outfile);
    return 0;

help:
    help();
}
