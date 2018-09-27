

all: mapper.o
	$(AR) -rsc libminiverse.a ssdis.o
	$(CC) -g driver.c libminiverse.a /usr/local/lib/libssdis.a /usr/lib/libcapstone.a -o driver

install: all
	cp miniverse.h /usr/local/include/miniverse.h
	cp libminiverse.a /usr/local/lib/libminiverse.a

clean:
	rm -f driver *.gch *.a *.o
