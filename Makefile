MUSL_PATH = ~/git/musl/lib

all: miniverse.o handlers.o
	$(AR) -rsc libminiverse.a miniverse.o handlers.o
	$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch
	nasm -f bin -l entry.lst entry.asm

UNPATCHED_TESTS := test0-basic test1-multiple-regions test2-modify-regions
PATCHED_TESTS := test3-callbacks test4-call-as-target test5-special-calls test6-return-addr test7-return-imm test8-odd-alignment test9-superset-special

$(UNPATCHED_TESTS): all
	$(CC) -m32 -g -I. tests/$@.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o $@

$(PATCHED_TESTS): all
	$(CC) -m32 -g -I. tests/$@.c -S -o $@.s
	python miniverse_spatcher.py $@.s
	$(CC) -m32 -g $@.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o $@

test: all $(UNPATCHED_TESTS) $(PATCHED_TESTS)

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a
	cp miniverse_spatcher.py /usr/local/bin/miniverse_spatcher.py

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f libminiversebin libminiverseflat binminiverseentry *.gch *.a *.o *.s test[0-9]-*
