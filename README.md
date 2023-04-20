# INTRODUCE 
simple ELF shellcode injection with c impl

# DETAIL
1. The core target is to find a crack between the two segments, like the following layout(from my another project ExParser):
```shell
LOAD                   0x2000
        .init               0x2000-0x201b
        .plt                0x2020-0x22c0
        .plt.got            0x22c0-0x22d0
        .plt.sec            0x22d0-0x2560
        .text               0x2560-0x5c72
        .fini               0x5c74-0x5c81
END                    0x5c81
-----------------------------------------------
LOAD                   0x6000
        .rodata             0x6000-0x728c
        .eh_frame_hdr       0x728c-0x7518
        .eh_frame           0x7518-0x80f8
END                    0x80f8
```
here exist a hole between 0x5c81 - 0x6000 and its' permission with X.

2. I need to inject my shellcode to the hole, What part I need to adjust?
    - The `.fini` section' size
    - The `LOAD` segment' size
    - modify the entry to 0x5c81(perserve the old entry)

- What prelude do?

prelude act as caller of shellcode, do something perserve state and jmp to shellcode and return to original logic. It let shellcode maker not worry about deal with diff binary.


prelude_inc.S provide two ptrs for size calculation, it will be embeded to my ElfInject. The only part we need to pass to ElfInject is shellcode which not contain the prelude.bin(cuz it 
have embeded in my ElfInject alreadly)

# LAYOUT
```shell
|                  |
|------------------| <-- last_sinfo.offset
|                  |                     ↑
|                  |                     |
|    content of    |              last_sinfo.size
|     section      |                     |
|                  |                     ↓
|------------------| <-- target->offset -|
|                  |                     ↑
|     vacuum       |                     |
|   for payload    |                target->size
|     inject       |                     |
|                  |                     ↓
|------------------| <-- elf->base + target->offset + target->size
|                  |                                      ↑
|      vacuum      |                                      |
|                  |                                      |
|------------------| <-- new segment start                |
|                  |                                  remaining
|                  |                                      |
|    ·········     |                                      |
|                  |                                      ↓
|------------------| <-- the end of file   ---------------|


```


# EXTRA

Not provide expand segment new cuz it too hard to debug...

# USAGE

```shell
./bin_generate.sh
xmake build
./build/linux/x86_64/debug/ElfInject test/ls build/shellcode.bin test/ls-injected
```


```shell
# squ @ squ-virtual-machine in ~/proj/ElfInject on git:master x [18:28:59] C:130
$ ./test/ls-injected .
This is a shellcode example
Hbin_generate.sh  build inc  load  README.md  script  shellcode  src  test  xmake.lua
```
