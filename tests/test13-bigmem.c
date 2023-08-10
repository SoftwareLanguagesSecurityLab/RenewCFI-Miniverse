/* Test allocating a large amount of memory
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
  return false;
}

int main(int argc, char** argv){

  register_handler(&my_is_target);

  /*
 0  31 c0                                            xor eax,eax
 2  e8 00 00 00 00                                   call 0x7
 7  40                                               inc	eax
 8  c3                                               ret
  */
	uint8_t orig_code[] = "\x31\xc0\xe8\x00\x00\x00\x00\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	
  for( int i = 0; i < 0x7000000/4; i+=0x100000 ){
	  mmap(code_buffer+i, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(code_buffer+i, orig_code, sizeof(orig_code));
    /* Try to make code executable; our mprotect hook will prevent this */
    mprotect(code_buffer+i, 0x10000, PROT_EXEC|PROT_READ);
    uint32_t res = ((uint32_t (*)())code_buffer+i)();
    assert( res == 2 );
  }

  printf("Ok\n");
	return 0;
}
