;nasm -f elf fstring.asm
BITS 32
GLOBAL get_fstring
SECTION .text
get_fstring:
	mov eax,[esp+4]
	cmp eax,0
        jz after
	mov eax,msg2
	ret
msg1:
	db 'mode: %d', 10, 0
msg2:
	db '%s', 10, 0
after:
	mov eax,msg1
	ret
