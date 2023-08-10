/* Test program expecting original return values
*/

#include "miniverse.h"
#include "inittester.h"
#include "handlers.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

#include <assert.h>

//#include <signal.h>
//#include <inttypes.h>
//#include <stdbool.h>

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
  switch( address ){
    case 0x7004000:
      return true;
  }
  return false;
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
  //mmap_hook(&mmap);
  //mprotect_hook(&mprotect);
  register_handler(&my_is_target);

  /* 
    Create code that jumps to a separate region, but both regions are
    allocated before we jump to either of them.  This caused a problem
    with miniverse, because in my current implementation I try to rewrite
    proactively *unless* the program hasn't jumped to rewritten code yet!
    I am waiting so that I can get the address of the first jit code region
    that is executed and the address of the code calling it.  That actually
    determines the value I set for the fixed offset.  However, if I wait
    until the first time jit code is executed to rewrite it, and if multiple
    regions are allocated before the first time code is executed, and if
    those regions jump between each other, then only the first jit region
    to be executed is rewritten and the cross-region jump has an empty
    mapping for the other regions, leading to a crash.
  */
  /*
 0  31 c0                                            xor	eax, eax
 2  40                                               inc	eax
 3  53                                               push	ebx
 4  bb 00 40 00 07                                   mov	ebx, 0x7004000
 9  ff e3                                            jmp	ebx
  */
	uint8_t orig_code1[] = "\x31\xc0\x40\x53\xbb\x00\x40\x00\x07\xff\xe3";
  /*
 0  40                                               inc	eax
 1  5b                                               pop	ebx
 2  c3                                               ret
  */
	uint8_t orig_code2[] = "\x40\x5b\xc3";

	void *code_buffer1 = (void*)0x7000000;
	void *code_buffer2 = (void*)0x7004000;
	
	mmap(code_buffer1, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mmap(code_buffer2, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer1, orig_code1, sizeof(orig_code1));
	memcpy(code_buffer2, orig_code2, sizeof(orig_code2));
	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer1, 0x1000, PROT_EXEC|PROT_READ);
        mprotect(code_buffer2, 0x1000, PROT_EXEC|PROT_READ);
        uint32_t res = ((uint32_t (*)())code_buffer1)();
        printf("Result: %d Expected: 2\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
