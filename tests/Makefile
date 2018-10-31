all:
	nasm -f elf fstring.asm
	nasm -f elf printer.asm 
	gcc -m32 test.c fstring.o printer.o -Wl,--section-start=.text=0x7000000 -o test

unmoved:
	nasm -f elf fstring.asm
	nasm -f elf printer.asm 
	gcc -m32 test.c fstring.o printer.o -o test

so:
	nasm -f elf fstring.asm
	nasm -f elf printer.asm 
	gcc -m32 fstring.h fstring.c fstring.o printer.o -shared -fPIC -o libtest.so 

clean:
	rm -f test *.o
