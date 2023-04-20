#!/bin/sh
mkdir -p build
as -o build/prelude.o shellcode/prelude.S
objcopy -O binary --only-section=.text build/prelude.o build/prelude.bin
as -o build/shellcode.o shellcode/shellcode.S
objcopy -O binary --only-section=.text build/shellcode.o build/shellcode.bin
cat build/prelude.bin build/shellcode.bin > payload.bin 
