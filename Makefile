MUSL_PATH = ~/git/musl/lib

all: miniverse.o handlers.o
	$(AR) -rsc libminiverse.a miniverse.o handlers.o
	$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch
	nasm -f bin -l entry.lst entry.asm

test: all
	#$(CC) -m32 -g driver.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver
	#$(CC) -m32 -g driver2.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver2
	#$(CC) -m32 -g driver3.c handlers.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver3
	#$(CC) -m32 -g driver4.c inittester.c -Ltests/ -ltest -o driver4
	$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver5
	# No hooking version (to test without rewriting anything)
	#$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver5
	$(CC) -m32 -g driver6.c inittester.c -o driver6
	$(CC) -m32 -g driver7.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver7
	$(CC) -m32 -g driver8.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver8
	$(CC) -m32 -g driver9.c -S -o driver9.s
	python miniverse_spatcher.py driver9.s
	$(CC) -m32 -g driver9.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver9
	$(CC) -m32 -g driver10.c -S -o driver10.s
	python miniverse_spatcher.py driver10.s
	$(CC) -m32 -g driver10.s libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver10

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a
	cp miniverse_spatcher.py /usr/local/bin/miniverse_spatcher.py

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f driver *.gch *.a *.o
