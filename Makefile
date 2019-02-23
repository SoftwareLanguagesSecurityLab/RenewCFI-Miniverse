MUSL_PATH = ~/git/musl/lib

all: mapper.o
	$(AR) -rsc libminiverse.a mapper.o
	$(CC) -m32 -Wall -Wextra -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a handlers.c $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	$(CC) -m32 -Wall -Wextra -g bpatch.c inittester.c -o bpatch

test: mapper.o
	$(AR) -rsc libminiverse.a mapper.o
	#$(CC) -m32 -g driver.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver
	#$(CC) -m32 -g driver2.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver2
	#$(CC) -m32 -g driver3.c handlers.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver3
	#$(CC) -m32 -g driver4.c inittester.c -Ltests/ -ltest -o driver4
	$(CC) -m32 -g driver5.c handlers.c libminiverse.a /usr/local/lib/libssdis.a /usr/local/lib/libudis86.a /usr/local/lib/libpagealloc.a $(MUSL_PATH)/libc.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver5
	# No hooking version (to test without rewriting anything)
	#$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver5
	$(CC) -m32 -g driver6.c inittester.c -o driver6

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a

%.o: %.c
	$(CC) -Wall -Wextra -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f driver *.gch *.a *.o
