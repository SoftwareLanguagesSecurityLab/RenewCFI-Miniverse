BITS 32

%define O_RDONLY 0x0

SECTION .text
_entry:
	call pic
pic:
	sub dword [esp], 5		; subtract offset of call instruction
	call open_miniverse		; returns fd in eax
	; mmap in contents of miniverse file
	mov edi, eax			; save fd so we can close the file
	mov ebx, [esp]			; load code start address
	add ebx, mmap_arg_struct	; load address of mmap arg
	mov esi, 6
mmap_arg_loop:
	push dword [ebx]
	sub ebx,4
	dec esi
	jnz mmap_arg_loop
	mov ebx, esp
	mov [ebx+16], eax		; load fd to right field of struct
	mov eax, 0x5a			; old_mmap
	int 0x80
	add esp, 24
	call close_miniverse
	; code after this point is untested and will likely be removed
	; copy bytes of library over from wherever they are loaded
	mov esi, [esp]
	add esi, miniverse_source_addr
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
	push dword [original_entry]
	push dword [esp+4]
	jmp [miniverse_entry]
open_miniverse:
	mov eax, 0x5			; open
	mov ebx, [esp+4]		; load base address
	add ebx, miniverse_filename	; file name
	mov ecx, O_RDONLY		; open as readonly ; edx (mode) ignored
	int 0x80
        ret
close_miniverse:
	mov eax, 0x6			; close
	mov ebx, edi			; fd
	int 0x80
	ret
	dd 0xf4f4f4f4		; addr
	dd 0x00000000		; len
	dd 0x00000000		; prot
	dd 0x00000000		; flags
mmap_arg_fd:
	dd 0x00000000		; fd
mmap_arg_struct:		; put mmap_arg_struct label at last element
	dd 0x00000000		; offset
miniverse_source_addr:
	dd 0x00000000		; loaded address of miniverse (may be non-exec)
miniverse_dest_addr:
	dd 0x00000000		; target address for miniverse to be loaded to
miniverse_entry:
	dd 0x00000000		; addr of entry point to miniverse (in target)
original_entry:
	dd 0x00000000		; addr of backed-up original entry point
miniverse_filename:
	db 'libminiverseflat', 0
