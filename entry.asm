BITS 32

SECTION .text
_entry:
	call pic
pic:
	sub dword [esp], 5		; subtract offset of call instruction
	; call mmap to allocate space for library
	mov eax, 0xc0			; old_mmap
	mov ebx, [esp]			; load code start address
	add ebx, mmap_arg_struct	; load address of mmap arg
	int 0x80
	; copy bytes of library over from wherever they are loaded
	mov esi, [esp]
	add esi, miniverse_addr
	mov esi, [esi]
	mov edi, [esp]
	add edi, mmap_arg_struct
	mov edi, [edi]
	mov ebx, [esp]
	add ebx, [mmap_arg_struct+4]
	mov ebx, [ebx]
bytes_copy:
	mov dword edx, [esi]
	mov dword [edi], edx
	add esi, 4
	add edi, 4
	sub ebx, 4
	jnz bytes_copy
	jmp _entry
mmap_arg_struct:
	dd 0xf4f4f4f4		; addr
	dd 0x00000000		; len
	dd 0x00000000		; prot
	dd 0x00000000		; flags
	dd 0x00000000		; fd
	dd 0x00000000		; offset
miniverse_addr:
	dd 0x00000000		; addr of miniverse library (may be non-exec)
