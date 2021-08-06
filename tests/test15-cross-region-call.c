/* Test direct calls, jumps, and returns across regions
*/

#include "miniverse.h"
#include "inittester.h"
#include "handlers.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

#include <assert.h>

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
  /* Setting the hlt as a target is important, as it tests for a bug in
     which I didn't record the mapping for indirect jumps correctly. */
  if( address == 0x7000002 || address == 0x7000009 || address == 0x700000f ||
      address == 0x7004008 || address == 0x700400d || address == 0x7004012 ||
      address == 0x7004013 || address == 0x7004018 ){
    return true;
  }
  return false;
}

int main(int argc, char** argv){

  register_handler(&my_is_target);

  /* 
    Create a simple region that can be called, and then create a second region
    that calls into it and then returns to the original region.  This tests
    both direct calls and returns across separated jit regions.
  */
  /*
7000000  31 c0                                            xor	eax, eax
7000002  40                                               inc	eax
7000003  6a 00                                            push	0
7000005  83 c4 04                                         add	esp, 4
7000008  c3                                               ret
7000009  40                                               inc	eax
700000a  e9 04 40 00 00                                   jmp	0x7004013
700000f  40                                               inc	eax
7000010  e9 03 40 00 00                                   jmp	0x7004018
  */
	uint8_t orig_code1[] = "\x31\xc0\x40\x6a\x00\x83\xc4\x04\xc3\x40\xe9\x04\x40\x00\x00\x40\xe9\x03\x40\x00\x00";
  /*
7004000  31 c0                                            xor	eax, eax
7004002  40                                               inc	eax
7004003  e8 fa bf ff ff                                   call	0x7000002
7004008  e8 f5 bf ff ff                                   call	0x7000002
700400d  e9 f7 bf ff ff                                   jmp	0x7000009
7004012  f4                                               hlt
7004013  e9 f7 bf ff ff                                   jmp	0x700000f
7004018  c3                                               ret
  */
	uint8_t orig_code2[] = "\x31\xc0\x40\xe8\xfa\xbf\xff\xff\xe8\xf5\xbf\xff\xff\xe9\xf7\xbf\xff\xff\xf4\xe9\xf7\xbf\xff\xff\xc3";

	void *code_buffer1 = (void*)0x7000000;
	void *code_buffer2 = (void*)0x7004000;
	
	mmap(code_buffer1, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mmap(code_buffer2, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer1, orig_code1, sizeof(orig_code1));
	memcpy(code_buffer2, orig_code2, sizeof(orig_code2));
	/* Try to make code executable; our mprotect hook will prevent this */
  mprotect(code_buffer1, 0x1000, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer1)();
  assert( res == 1 );
  mprotect(code_buffer2, 0x1000, PROT_EXEC|PROT_READ);
  res = ((uint32_t (*)())code_buffer2)();
  assert( res == 5 );

  puts("Ok");
	return 0;
}
