[bits 32]
[section .text]

hash_search_IAT:
			pushad
			push ebp
			mov ebp, esp
			xor eax, eax
			mov edx, [fs:0x30]			; PEB
			mov ebx, [edx + 0x8]			;  _IMAGE_DOS_HEADER = imagebase = PEB + 0x8						; push IMAGE_BASE
			mov edx, [ebx + 0x3c]			; [e_lfanew] = IMAGE_NT_HEADERS = [DOS_Header + 0x3c]

			add edx, ebx
			mov edx, [edx + 0x80]			; IMAGE_DATA_DIRECTORY = IMAGE_NT_HEADERS + 0x78

			;Find IAT
											; IAT offset = IMAGE_DATA_DIRECTORY[2]
			add edx, ebx					; edx = IID
											; IID[0][0] --> OriginalFirstThunk --> string to dll funcName
											; IID[0][3] --> string to dllName
											; IID[0][4] --> FirstThunk
		next_mod:
			mov esi, [edx + 4 * 3]			; pointer to dllName
			add esi, ebx
			push esi
			call strLen
			pop esi
			mov ecx, eax
			xor edi, edi
		loop_modname:
			lodsb
			cmp al, 'a'
			jl not_lowercase
			sub al, 0x20
		not_lowercase:
			ror edi, 13
			add edi, eax
			loop loop_modname

			; Now we have the module hash in edi

			push edx						; edx == IID
			push edi						; module hash
			xor ecx, ecx
			mov edx, [edx]
			add edx, ebx
			; process to iterate the IAT
		get_next_func:
			push ecx
			mov ecx, [edx + ecx]		; offset pointer to first dll funcName offset
			test ecx, 0x80000000
			jnz get_next_mod
			jecxz get_next_mod						; if ecx == 0 next_mod
			add ecx, ebx						; pointer to first funcName offset


			; if [ecx] == 0, this IAT is finish
			add ecx, 2							; First byte is No.
			mov esi, ecx
			push esi
			call strLen
			pop esi
			mov ecx, eax
			xor eax, eax
			xor edi, edi
		loop_funcname:
			lodsb
			ror edi, 13
			add edi, eax
			loop loop_funcname
			add edi, [ebp - 8]				; add module hash and func hash
			cmp edi, [ebp + 40]
			jz finish
			pop ecx
			add ecx, 4
			jmp get_next_func

			; if found, fix up the stack ans use IID[?][4] addr
		finish:
			pop ecx
			pop edi
			pop edx
			mov edx, [edx + 16]
			add edx, ebx					; ecx = func No, edx = IAT
			mov eax, [edx + ecx]
			mov [ebp + 40], eax
			mov esp, ebp
			pop ebp
			popad
			mov eax, [esp + 4]
			ret


		get_next_mod:
			pop ecx
			pop edi
			pop edx							; edx == IID
			add edx, 20
			jmp short next_mod


		strLen:
			push esi
			push ecx
			mov esi, [esp + 12]
			xor ecx, ecx
		strLenLoop:
			lodsb
			cmp eax, 0x00
			jz strLenRet
			inc ecx
			jmp strLenLoop
		strLenRet:
			mov eax, ecx
			pop ecx
			pop esi
			ret
