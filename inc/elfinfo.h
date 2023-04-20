#ifndef __ELF_INFO_H__
#define __ELF_INFO_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "types.h"

#define MAX_SH_NAMELEN 128

/* section header OK */
typedef struct {
    char name[MAX_SH_NAMELEN];
    uint32_t offset;
    uint32_t size;
    uint32_t secidx;   /* index of section table for following fixup */
    uint32_t segidx;   /* index of segment table for following fixup */
}shinfo;


typedef struct {
    int fd;
    int size;
    uint8_t *base;
} fmap_t;

extern void init_fmap(fmap_t *file, const char *filename);
extern void deinit_fmap(fmap_t *file);

/* target_t section in which our shellcode will inject */
typedef struct {
    u64 offset;
    u64 size;
}target_t;

extern uint8_t *g_prelude_start;
extern uint8_t *g_prelude_end;

/**
 * Fixup associated section's offset
 *
 * @param elf ELF binary struct
 * @param last_sinfo the section will be extended
 * @param target contain the address into which shellcode and prelude will be injected
 * @param shcd_size Size of shellcode
 */
void adjust_size(fmap_t *elf, shinfo *last_sinfo, target_t *target, size_t shcd_size);

/**
 * find last section in executable segment
 *
 * @param elf ELF binary struct
 * @param shcd_size Size of shellcode(not contain the prelude)
 * @return shinfo structure containing information on section to be expanded, or NULL on failure
 */
shinfo *find_last_ex_section(fmap_t *elf, size_t shcd_size);

/**
 * Overwrite ELF e_entry so that it points to the injected shellcode
 *
 * @param elf ELF binary struct
 * @param target contain the address into which shellcode and prelude will be injected
 * @param old_entry Pointer to output original e_entry offset
 */
void adjust_entry(fmap_t *elf, target_t *target, uint32_t *old_entry);

/**
 * Write back to file 
 * 
 * @param elf ELF binary struct
 * @param shcd shellcode binary struct
 * @param outfile output file name
 * @param target contain the address into which shellcode and prelude will be injected
 * @param old_entry Pointer to output original e_entry offset
*/
void writeback(fmap_t *elf, fmap_t *shcd, char *outfile, target_t *target, uint32_t* old_entry);
#endif
