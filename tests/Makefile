all:
	nasm -f elf fstring.asm
	nasm -f elf printer.asm 
	gcc -m32 test.c fstring.o printer.o -Wl,--section-start=.text=0x7000000 -o test

clean:
	rm -f test *.o
