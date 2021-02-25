# Don't use musl due to argument size mismatch for mmap wrapper
#MUSL_PATH = ~/git/musl/lib


all: miniverse.o handlers.o
	$(AR) -rsc libminiverse.a miniverse.o handlers.o
	#$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	#$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch
	#nasm -f bin -l entry.lst entry.asm

UNPATCHED_TESTS := test0-basic brokentest-multiple-regions test2-modify-regions
PATCHED_TESTS := test1-pointers-in-stack test3-callbacks test4-call-as-target test5-special-calls test6-return-addr test7-return-imm test8-odd-alignment test9-superset-special test10-cross-boundary test12-multiple-initial-regions
HIGH_ADDR_TEST := test11-high-addr

$(UNPATCHED_TESTS): all
	$(CC) -m32 -g -I. tests/$@.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o $@

$(PATCHED_TESTS): all
	$(CC) -m32 -g -I. tests/$@.c -S -o $@.s
	python miniverse_spatcher.py $@.s
	$(CC) -m32 -g $@.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o $@

$(HIGH_ADDR_TEST): all
	$(CC) -m32 -g -I. tests/$@.c -S -o $@.s
	python miniverse_spatcher.py $@.s
	$(CC) -m32 -g $@.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -Wl,-Ttext-segment,0xd0000000 -o $@

test: all $(UNPATCHED_TESTS) $(PATCHED_TESTS) $(HIGH_ADDR_TEST)

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a
	cp miniverse_spatcher.py /usr/local/bin/miniverse_spatcher.py

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f libminiversebin libminiverseflat binminiverseentry *.gch *.a *.o *.s test[0-9]-*
