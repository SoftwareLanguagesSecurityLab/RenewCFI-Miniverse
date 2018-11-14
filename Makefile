

all: mapper.o
	$(AR) -rsc libminiverse.a mapper.o
	$(CC) -m32 -g driver.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver
	$(CC) -m32 -g driver2.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver2
	$(CC) -m32 -g driver3.c handlers.c libminiverse.a -Ltests/ -ltest /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o driver3
	$(CC) -m32 -g driver4.c inittester.c -Ltests/ -ltest -o driver4
	$(CC) -m32 -g -fPIC -static dummy.c libminiverse.a /usr/local/lib/libssdis32.a /usr/lib/libcapstone32.a -o libminiversebin

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a

%.o: %.c
	$(CC) -m32 -g -c $< -o $@

clean:
	rm -f driver *.gch *.a *.o
