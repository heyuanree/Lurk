;shellcode_framework_win32 

[bits 32]
global _GetFuncAddress
global _str2dw
[section .text]

;__cdecl
_str2dw:
    ;get a value by a string(the name of the function)
    push ebp
    mov ebp,esp
    push esi
    push edi
    push ebx
    mov esi,[ebp+8]	;get the address of the string
    xor ebx,ebx
tag1:
    lodsb
    cmp al,0
    je exit
    movzx edx,al
    mov eax,edx
    mov ecx,ebx
    ror ecx,0x0d
    cmp al,'a'
    jb tag2
    sub eax,32
    add ecx,eax
    jmp tag3
tag2:
    add ecx,eax
tag3:
    mov ebx,ecx
    jmp tag1
exit:
    mov eax,ebx
    pop ebx
    pop edi
    pop esi
    mov esp,ebp
    pop ebp
    ret 


;__cdecl
_GetFuncAddress:
    push ebp
    mov ebp,esp
    sub esp,10h
    push ebx
    push edi
    push esi
    mov ebx,dword [fs:30h]      ;the pointer of _PEB
    mov edi,dword [ebx+0Ch]     ; _PEB->Ldr
    mov esi,dword [edi+14h]     ; Ldr->InMemoryOrderModuleList
	
    lodsd
    mov edi,eax
    mov dword [ebp-4h],edi      ;save the first LDR_DATA_TABLE_ENTRY
    ;edi as a pointer of the IDR_DATA_TABLE_ENTRY 
s1:	
    mov	ebx, dword [edi + 10h]  ; DllBase
    mov edx, dword [ebx+3ch]    ;_IMAGE_DOS_HEADER->e_lfnew
    add edx, ebx
    add edx, 18h                ;_IMAGE_NT_HEADER32->OptionalHeader
    add edx, 60h                ;_IMAGE_OPTIONAL_HEADER32->IMAGE_DATA_DIRECTORY
    cmp dword [edx],0
    je s2
    mov edx,dword [edx]
    add edx,ebx
    mov dword [ebp-0ch],edx     ;save the IMAGE_EXPORT_DIRECOTRY's address
    mov ecx,dword [edx+18h]	    ;save IMAGE_EXPORT_DIRECTORY->NumberofFunctions
    dec ecx
    mov edx,dword [edx+20h]
    add edx,ebx	                ;get the array of functions'name
s3:
    push dword [edx +ecx*4]
    pop dword [ebp-8h]
    add dword [ebp-8h],ebx
    push edx
    push ecx
    push dword [ebp-8h]
    call _str2dw
    add  esp,4h
    cmp eax,dword [ebp+8h]      ;compare with the param
    pop ecx
    pop edx
    jne s4
    mov eax,dword [ebp-0ch]     ;get the address of IMAGE_EXPORT_DIRECTORY
    mov eax,dword [eax+24h]
    add eax,ebx
    mov ax,word [eax+ecx*2]
    and eax,0x0000ffff
    mov dword [ebp-10h],eax     ;save the index of AddressofNameOrdinals
    mov eax,dword [ebp-0ch]
    push esi
    mov esi,dword [ebp-10h]
    mov eax,dword [eax+1ch]
    add eax,ebx
    mov eax,dword [eax+esi*4]
    add eax,ebx
    pop esi
    jmp _exit
s4:
    loop s3
s2:	
    mov esi,dword [edi]
    mov edi,esi
    cmp edi,dword [ebp-4h]  ; 
    jne s1	
_exit:
    pop esi
    pop edi
    pop ebx
    add esp,10h
    mov esp,ebp
    pop ebp
    ret ;keep silent of esp
	
	
	