# Don't use musl due to argument size mismatch for mmap wrapper
#MUSL_PATH = ~/git/musl/lib


all: miniverse.o handlers.o
	$(AR) -rsc libminiverse.a miniverse.o handlers.o
	#$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	#$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch
	#nasm -f bin -l entry.lst entry.asm

glibc_install=${HOME}/git/glibc/BUILD/install

standalone: all
	_XOPEN_SOURCE=600 $(CC) -Wl,-Ttext-segment=0xdeadb000 -m32 -static-pie -fPIE -fno-stack-protector -g -I. \
  -L "${glibc_install}/lib" \
  -I "${glibc_install}/include" \
  -Wl,--rpath="${glibc_install}/lib" \
  -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux.so.2" \
  -v -nostartfiles \
  ${glibc_install}/lib/crti.o \
  ${glibc_install}/lib/crtn.o \
  ${glibc_install}/lib/crt1.o \
  stub.c miniverse.c handlers.c /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o $@ 

UNPATCHED_TESTS := brokentest-multiple-regions
PATCHED_TESTS := test0-basic test1-pointers-in-stack test2-modify-regions test3-callbacks test4-call-as-target test5-special-calls test6-return-addr test7-return-imm test8-odd-alignment test9-superset-special test10-cross-boundary test12-multiple-initial-regions test13-bigmem test14-esp-call test15-cross-region-call test16-loop test17-distant-regions test18-mmap-len
HIGH_ADDR_TEST := test11-high-addr
STANDALONE_TEST := test-standalone

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

$(STANDALONE_TEST): standalone
	$(CC) -m32 -g -I. tests/$@.c -S -o $@.s
	python miniverse_spatcher.py $@.s
	$(CC) -m32 -c -g -I. tests/$@.S -o $@-asm.o
	$(CC) -m32 -g -I. $@.s $@-asm.o -o $@

test: all $(UNPATCHED_TESTS) $(PATCHED_TESTS) $(HIGH_ADDR_TEST) $(STANDALONE_TEST)

test-clang: CC=clang
test-clang: test

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a
	cp miniverse_spatcher.py /usr/local/bin/miniverse_spatcher.py
	cp standalone /usr/local/bin/miniverse-standalone

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -O2 -c $< -o $@

clean:
	rm -f libminiversebin libminiverseflat binminiverseentry *.gch *.a *.o *.s test[0-9]*-*
