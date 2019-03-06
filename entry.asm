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
	add ebx, [mmap_arg_struct+4]	; miniverse_dest_addr
	mov ebx, [ebx]
bytes_copy:
	mov dword edx, [esi]
	mov dword [edi], edx
	add esi, 4
	add edi, 4
	sub ebx, 4
	jnz bytes_copy
	push [original_entry]
	push [esp+4]
	jmp [miniverse_entry]
mmap_arg_struct:
	dd 0xf4f4f4f4		; addr
	dd 0x00000000		; len
	dd 0x00000000		; prot
	dd 0x00000000		; flags
	dd 0x00000000		; fd
	dd 0x00000000		; offset
miniverse_source_addr:
	dd 0x00000000		; loaded address of miniverse (may be non-exec)
miniverse_dest_addr:
	dd 0x00000000		; target address for miniverse to be loaded to
miniverse_entry:
	dd 0x00000000		; addr of entry point to miniverse (in target)
original_entry:
	dd 0x00000000		; addr of backed-up original entry point
