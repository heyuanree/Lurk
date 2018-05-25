[BITS 32]
[section .text]

push 0xEEFB84AE
call hash_search_IAT
pop eax
push 0
push 0
push 0
push 0
call eax
ret