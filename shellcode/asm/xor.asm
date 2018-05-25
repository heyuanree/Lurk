[bits 32]
[section .mtext]

;   funcSize
;   ptrSMCSize
;   ptrSMCFunc
;   key

xor:
    push ebp
    mov ebp, esp
    push ecx

_conl:
    mov dword [ebp-4], 0
    jmp _local2

_local1:
    mov eax, dword [ebp-4]
    inc eax                 ;dec eax
    mov dword [ebp-4], eax

_local2:
    mov ecx, dword [ebp-4]
    call ptrSMCSize
    cmp ecx, [cs:ebx+2]
    jz exit

_local3:
    mov eax, dword [ebp-4]
    xor edx, edx
    call keySize
    mov ecx, [cs:ebx+2]
    div ecx
    call key
    movsx edx, byte [edx+ebx+2]
    call ptrSMCFunc
    add ebx, 2
    mov eax, ebx
    add eax, dword [ebp-4]
    movzx ecx, byte [cs:eax]
    xor ecx, edx
    call ptrSMCFunc
    add ebx, 2
    mov edx, ebx
    add edx, dword [ebp-4]
    mov byte [edx], cl

    jmp _local1

%include "{xor_config_file}"

exit:
    mov esp, ebp
    pop ebp
    call ptrSMCFunc+0x7

