BITS 32

%define O_RDONLY 0x0

SECTION .text
_entry:
	call pic
pic:
	sub dword [esp], 5		; subtract offset of call instruction
	pop edi				; save address of entry point in edi
	push edx			; save original value of edx
	call open_miniverse		; returns fd in eax
	; mmap in contents of miniverse file
	mov edx, eax			; save fd so we can close the file
	mov ebx, edi			; load code start address
	add ebx, mmap_arg_struct	; load address of mmap arg
	mov esi, 6
mmap_arg_loop:
	push dword [ebx]
	sub ebx,4
	dec esi
	jnz mmap_arg_loop
	mov ebx, esp
	mov [ebx+16], edx		; load fd to right field of struct
	mov eax, 0x5a			; old_mmap
	int 0x80
	add esp, 24
	call close_miniverse
	lea esi, [edi+entry_filename]
	push dword esi			; push address of entry filename
	push dword edi			; push entry point address
	push dword edi			; push entry point address (for ret)
        mov esi, [edi+miniverse_entry]	; retrieve address of miniverse entry
	jmp esi				; jump to library entry
open_miniverse:
	mov eax, 0x5			; open
	mov ebx, edi			; load base address
	add ebx, miniverse_filename	; file name
	mov ecx, O_RDONLY		; open as readonly ; edx (mode) ignored
	int 0x80
        ret
close_miniverse:
	mov eax, 0x6			; close
	mov ebx, edx			; fd
	int 0x80
	ret
	dd 0xf4f4f4f4			; addr
	dd 0x00000000			; len
	dd 0x00000000			; prot
	dd 0x00000000			; flags
mmap_arg_fd:
	dd 0x00000000			; fd
mmap_arg_struct:			; label mmap_arg_struct at last element
	dd 0x00000000			; offset
miniverse_entry:
	dd 0x00000000			; addr of miniverse entry (in mmapped)
miniverse_filename:
	db 'libminiverseflat', 0	; filename of miniverse library
entry_filename:
	db 'binminiverseentry', 0	; filename of binary's saved entry
