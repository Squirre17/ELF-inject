#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
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
    void *data = NULL;

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

    data = (void *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (!data) {
        PANIC("Failed to map file");
    }

    file = (fmap_t *)malloc(sizeof(fmap_t));
    if (!file) {
        FAPANICTAL("Failed to allocate memory for file mapping");
    }

    file->fd = fd;
    file->size = size;
    file->data = data;

    return;
}

void deinit_fmap(fmap_t *file)
{
    if (!file)
        return;

    if (file->data)
        munmap(file->data, file->size);
    if (file->fd != -1)
        close(file->fd);
    free(file);
}