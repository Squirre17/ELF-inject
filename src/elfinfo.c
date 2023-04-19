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

    file = (fmap_t *)malloc(sizeof(fmap_t));
    if (!file) {
        FAPANICTAL("Failed to allocate memory for file mapping");
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
    free(file);
}

shinfo *find_last_ex_section(fmap_t *elf, size_t shcd_size) {

    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Phdr *phtable;
    Elf64_Shdr *shtable;
    char *shstr;
    uint32_t segment_end;
    shinfo *sinfo = NULL;
    size_t i, j;
    uint32_t prelude_size;
    bool found = false;

    ehdr    = (Elf64_Ehdr *)elf->base;
    phdr    = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);
    phtable = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);
    shtable = (Elf64_Shdr *)((uintptr_t)elf->base + ehdr->e_shoff);
    shstr = (char *)((uintptr_t)elf->base + shtable[ehdr->e_shstrndx].sh_offset);

    for (i = 0; i < ehdr->e_phnum; i++) {

        /* try to find a segment with X permission */
        if (!(phdr[i].p_flags & PF_X))
            continue;

        OK("Found executable segment at 0x%08lx (size:%08lx)\n", phdr[i].p_offset, phdr[i].p_memsz);

        /* Found the executable segment, now find the last section in the segment */
        segment_end = phdr[i].p_offset + phdr[i].p_memsz;

        for (j = 0; j < ehdr->e_shnum; j++) {

            if (shtable[j].sh_addr + shtable[j].sh_size == segment_end) {

                found = true;
                sinfo = (shinfo *)malloc(sizeof(shinfo));

                if (!sinfo) {
                    PANIC("malloc failed");
                }

                strncpy(sinfo->name, shstr + shtable[j].sh_name, MAX_SH_NAMELEN-1);
                sinfo->offset = (uint32_t *)&shtable[j].sh_offset;
                sinfo->size   = (uint32_t *)&shtable[j].sh_size;
                break;
            }
        }

        if (found == false) {
            ACK("No sections in segment!? Searching for a new RX segment ...");
            continue;
        }

        OK("Found %s at 0x%08x with a size of %u bytes. within segment (0x%08x-0x%08x)", 
            sinfo->name, *sinfo->offset, *sinfo->size, phtable[i].p_offset, phtable[i].p_offset +  phtable[i].p_filesz);

        /* Check if the payload is able to fit without expanding the segment past the next page boundary */
        prelude_size = (uintptr_t)&g_prelude_end - (uintptr_t)&g_prelude_start;

        if (shtable[j+1].sh_addr - shtable[j].sh_addr - shtable[j].sh_size >= shcd_size + prelude_size) {
            OK("Payload can fit on last page of RX segment");
            goto out;
        }else {
            FATAL("unimpl segment expand");
        }

    }
    FATAL("RX segment not found");
    // exit(1);// TODO: temporary 
out:
    return sinfo;

}

/**/
void adjust_offset(fmap_t *elf, shinfo *last_sinfo, target_t *target, size_t shcd_size)
{
    Elf64_Ehdr* ehdr;
    size_t      size;
    uint32_t    newoff;
    Elf64_Shdr* shtable;
    size_t      i;
    uint32_t    prelude_size;

    /* build/prelude.bin between the g_prelude_end and g_prelude_start */
    prelude_size = (uintptr_t)&g_prelude_end - (uintptr_t)&g_prelude_start;

    ehdr = (Elf64_Ehdr *)elf->base;

    /* Set patch information */
    size = *last_sinfo->size;
    target->addr = *last_sinfo->offset + size; /* insert payload into the end of last section */
    target->size = shcd_size;

    /* Fix up size */
    INFO("Expanding %s size by %lu bytes...", last_sinfo->name, shcd_size + prelude_size);
    *last_sinfo->size = size + shcd_size + prelude_size;

    Elf64_Phdr *phdr = (Elf64_Phdr *)((uintptr_t)elf->base + ehdr->e_phoff);

    INFO("Adjusting Program Headers ...");
    for (i = 0; i < ehdr->e_phnum; i++) {

        /* BUG: if two segments have X permission ? */
        if (phdr[i].p_flags & PF_X) {
            INFO("Adjusting RX segment program header size ...");
            phdr[i].p_filesz += shcd_size + prelude_size;
            phdr[i].p_memsz += shcd_size + prelude_size;
        }
    }

    //TODO: no necessary here?
    
    // INFO("Adjusting ELF header offsets ...");
    // if (ehdr->e_shoff > target->addr)
    //     ehdr->e_shoff = ehdr->e_shoff + patch_size + prelude_size;

    // if (ehdr->e_phoff > target->addr)
    //     ehdr->e_phoff = ehdr->e_phoff + patch_size + prelude_size;

    return;
}

void adjust_entry(fmap_t *elf, target_t *target, uint32_t *old_entry)
{
    Elf64_Ehdr *ehdr;
    INFO("Modifying ELF e_entry to point to the patch at 0x%08x ...", target->addr);
    ehdr = (Elf64_Ehdr *)elf->base;
    *old_entry = ehdr->e_entry;
    ehdr->e_entry = (uint32_t)target->addr;
}
