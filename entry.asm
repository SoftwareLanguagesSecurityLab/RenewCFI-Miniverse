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
	mov ebx, [esp]
        add esp,4
	mov esi, [ebx+miniverse_filename]
	push dword esi
        mov esi, [ebx+entry_filename]
	push dword esi
        mov esi, [ebx+miniverse_entry]
	jmp esi
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
miniverse_entry:
	dd 0x00000000		; addr of entry point to miniverse (in target)
miniverse_filename:
	db 'libminiverseflat', 0	; filename of miniverse library
entry_filename:
	db 'binminiverseentry', 0	; filename of binary's saved entry
