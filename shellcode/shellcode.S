.intel_syntax noprefix

jmp past

message:
    .ascii "This is a shellcode example\n"

past:
    mov rdi, 1                    /* STDOUT file descriptor */
    lea rsi, [rip + message]      /* Pointer to message string */
    mov rdx, 29                   /* Message size */
    mov rax, 1                    /* Write syscall number */
    syscall                       /* Execute system call */
    ret                           /* Return back to caller */