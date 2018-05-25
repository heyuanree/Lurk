[bits 32]
[section .mtext]

find_function :
    push ebp
    mov ebp, esp
    mov eax, [fs:0x30]					;fs points to teb in user mode，get pointer to peb
    mov eax, [eax + 0x0c]					;get peb->ldr
    mov eax, [eax + 0x14]					;get peb->ldr.InMemoryOrderModuleList.Flink(1st entry)
module_loop :
    mov eax, [eax]							;skip the first entry or get the next entry
    mov esi, [eax + 0x28]					;get the BaseDllName->Buffer
    cmp byte [esi + 0x0c], '3'			;test the module's seventh's wchar is '3' or not，kernel32.dll
    jne module_loop

                                            ;====================================
                                            ;find kernel32.dll module
                                            ;====================================
    mov eax, [eax + 0x10]					;LDR_DATA_TABLE_ENTRY->DllBase

                                            ;====================================
                                            ;kernel32.dll PE Header
                                            ;====================================
    mov edi, eax
    add edi, [edi + 0x3c]					;IMAGE_DOS_HEADER->e_lfanew

                                            ;====================================
                                            ;kernel32.dll export directory table
                                            ;====================================
    mov edi, [edi + 0x78]					;IMAGE_NT_HEADERS->OptinalHeader.DataDirectory[EAT].VirtualAddress
    add edi, eax

    mov ebx, edi							; ebx is EAT's virtual address,we’ll use it later

                                            ;====================================
                                            ;kernel32.dll Name Pointer Table
                                            ;====================================

    mov edi, [ebx + 0x20]					;IMAGE_EXPORT_DESCRIPTOR->AddressOfNames RVA
    add edi, eax

    xor ecx, ecx							;NameOrdinals

name_loop :
    mov esi, [edi + ecx * 4]
    add esi, eax
    inc ecx
    mov edx, [esp + 8]						;first parameter
    cmp dword [esi], edx
    jne name_loop
    mov edx, [esp + 0xc]					;second parameter
    cmp dword [esi + 4], edx
    jne name_loop

                                            ;======================================
                                            ;kernel32.dll Ordinal Table
                                            ;======================================
    mov edi, [ebx + 0x24]
    add edi, eax
    mov ecx, [edi + ecx * 2]
    and ecx, 0xFFFF							;cause ordinal is USHORT of size,so we just use its lower 16-bits

                                            ;======================================
                                            ;kernel32.dll Address Table
                                            ;======================================
    mov edi, [ebx + 0x1c]
    add edi, eax
    dec ecx									;subtract ordinal base
    sal ecx, 2
    mov edi, [edi + ecx]
    add eax, edi

    pop ebp
    ret 8
