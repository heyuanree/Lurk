[bits 32]
[section .text]

    push 0x37F58798
    call hash_search_IAT
    pop eax
    push 0x0000006c     ; messageBoxDll.dll
    push 0x6c642e6c
    push 0x6c44786f
    push 0x42656761
    push 0x7373656d
    push esp
    call eax
    pop ebx
    pop ebx
    pop ebx
    pop ebx
    pop ebx
    ret
