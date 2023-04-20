#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SHELLCODE_FILE "payload.bin"

int main() {
    FILE *fp;
    char *shellcode;
    size_t shellcode_len;
    void *map;

    // 打开文件，获取文件大小
    fp = fopen(SHELLCODE_FILE, "rb");
    fseek(fp, 0L, SEEK_END);
    shellcode_len = ftell(fp);
    rewind(fp);

    // 分配内存，读取文件内容
    shellcode = malloc(shellcode_len);
    fread(shellcode, sizeof(char), shellcode_len, fp);
    fclose(fp);

    // 分配可读写、可执行的内存映射区
    #define MAP_ANONYMOUS	0x20
    map = mmap(NULL, shellcode_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    // 将shellcode复制到映射区中
    memcpy(map, shellcode, shellcode_len);

    // 调用映射区中的函数
    ((void(*)())map)();

    // 释放内存
    munmap(map, shellcode_len);
    free(shellcode);

    return 0;
}
