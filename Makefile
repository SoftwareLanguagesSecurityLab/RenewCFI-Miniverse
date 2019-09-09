MUSL_PATH = ~/git/musl/lib

all: miniverse.o handlers.o
	$(AR) -rsc libminiverse.a miniverse.o handlers.o
	$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch
	nasm -f bin -l entry.lst entry.asm

test: all
	$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver5
	# No hooking version (to test without rewriting anything)
	#$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver5
	$(CC) -m32 -g driver7.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver7
	$(CC) -m32 -g driver8.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver8
	$(CC) -m32 -g driver9.c -S -o driver9.s
	python miniverse_spatcher.py driver9.s
	$(CC) -m32 -g driver9.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver9
	$(CC) -m32 -g driver10.c -S -o driver10.s
	python miniverse_spatcher.py driver10.s
	$(CC) -m32 -g driver10.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver10
	$(CC) -m32 -g driver11.c -S -o driver11.s
	python miniverse_spatcher.py driver11.s
	$(CC) -m32 -g driver11.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver11
	$(CC) -m32 -g driver-old-addr.c -S -o driver-old-addr.s
	python miniverse_spatcher.py driver-old-addr.s
	$(CC) -m32 -g driver-old-addr.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver-old-addr

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a
	cp miniverse_spatcher.py /usr/local/bin/miniverse_spatcher.py

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f libminiversebin libminiverseflat binminiverseentry *.gch *.a *.o *.s
