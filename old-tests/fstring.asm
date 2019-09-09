;nasm -f elf fstring.asm
BITS 32
GLOBAL get_fstring:function
GLOBAL get_fstring_indirect:function
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

get_fstring_indirect:
	mov eax,[esp+4]
        and eax,0x1
	mov ecx,table
	mov ecx,[ecx+4*eax]
	jmp ecx
table:
	dd get_msg1
	dd get_msg2
get_msg1:
	mov eax,msg1
	ret
get_msg2:
	mov eax,msg2
	ret
