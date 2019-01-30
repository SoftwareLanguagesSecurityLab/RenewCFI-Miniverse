MUSL_PATH = ~/git/musl/lib

all: mapper.o
	$(AR) -rsc libminiverse.a mapper.o
	$(CC) -m32 -g driver.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver
	$(CC) -m32 -g driver2.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver2
	$(CC) -m32 -g driver3.c handlers.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver3
	$(CC) -m32 -g driver4.c inittester.c -Ltests/ -ltest -o driver4
	$(CC) -m32 -g driver5.c handlers.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -Wl,-wrap=mmap -Wl,-wrap=mprotect -o driver5
	# No hooking version (to test without rewriting anything)
	#$(CC) -m32 -g driver5.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver5
	$(CC) -m32 -g driver6.c inittester.c -o driver6
	# Clang is not properly generating PIC for my function pointer!  This breaks the code when it
	# is moved!
	#$(CC) -m32 -g -fPIC -fPIE -pie -shared -static -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a handlers.c $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin
	$(CC) -m32 -g -fPIE -shared -static -pie -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a handlers.c $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -Wl,-wrap=printf -o libminiversebin
	# gcc correctly generates PIC for the function pointer I am passing as the handler, but
	#I can't compile with gcc because it generates plt entries and calls through those EVEN
	# WITHIN THE SAME BINARY, as everything is supposed to be statically linked!
	# It has to try to handle lazy binding with the GOT or something, and so it breaks things
	#$(CC) -m32 -g -fPIC -shared -static -nostdlib dummy.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a handlers.c $(MUSL_PATH)/libc.a -lgcc -Wl,-wrap=mmap -Wl,-wrap=mprotect -o libminiversebin

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a

%.o: %.c
	$(CC) -m32 -fPIE -shared -g -c $< -o $@

clean:
	rm -f driver *.gch *.a *.o
