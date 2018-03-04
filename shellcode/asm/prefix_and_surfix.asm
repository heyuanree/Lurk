[bits 32]
[section .text]

%include "{include_file}"

start:
    pushfd
    pushad

entry:
    {entry}

end:
    popad
    popfd
    {patched_inst}
    {jmp_patched_next_inst}