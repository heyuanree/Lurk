[bits 32]
[section .text]

loadLibrary:
    push 0x7262694c     ;Libr
    push 0x64616f4c     ;load
    call find_function
    call messageBoxDll
    add ebx, 2
    push ebx
    call eax
    push eax
    push 0x41636f72     ;rocA
    push 0x50746547     ;GetP
    call find_function
    pop ecx
    call TestProc
    add ebx, 2
    push ebx
    push ecx
    call eax
    call eax

messageBoxDll:
    call $+5
    pop ebx
    ret
    db "messageBoxDll.dll"
    db 0x000000

TestProc:
    call $+5
    pop ebx
    ret
    db "TestProc"
    db 0x00000000
