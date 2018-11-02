;nasm -f elf fstring.asm
BITS 32
EXTERN get_fstring_c
EXTERN get_fstring
EXTERN get_fstring_indirect
EXTERN printf
GLOBAL print_stuff:function
GLOBAL print:function
SECTION .text
print_stuff:
	push 0x0
	call get_fstring_indirect
	;mov [esp], eax
	;push 0x1
	add esp,4
	mov edx, [esp+4]
	push edx
	push eax
	call printf
	pop eax
	pop eax

	push 0x1
	call get_fstring_indirect
	pop edx
        push eax
	mov edx, [esp+8]
	push edx
	call get_fstring_c
        xchg eax, [esp+4]
	mov [esp],eax
	call printf
	pop eax
	pop eax
	
	;mov eax, 0x1
	;push eax
	;mov edx,[esp+8]
	;cmp eax,0
	;pop eax
        ;jz after
	;mov eax,msg2
	ret
;msg1:    db "Hello World",10     ; the string to print, 10=cr
;len1:    equ $-msg1               ; "$" means "here"
                                ; len is a value, not an address
;msg2:    db "Hello World 2",10     ; the string to print, 10=cr
;len2:    equ $-msg2               ; "$" means "here"
                                ; len is a value, not an address
;after:
;	mov eax,msg1
;	ret
;print:
;	push ebx
;       mov     edx,8         ; arg3, length of string to print
;        mov     ecx,[esp+8]    ; arg2, pointer to string
;        mov     ebx,1           ; arg1, where to write, screen
;        mov     eax,4           ; write sysout command to int 80 hex
;        int     0x80            ; interrupt 80 hex, call kernel
;	pop ebx
;	ret
	
print:
	push 0x0
	call print_stuff
	pop eax
	push 0x1
	call print_stuff
	pop eax
	mov eax, [esp+4]
	push eax
	call get_fstring
	pop ecx
	ret
