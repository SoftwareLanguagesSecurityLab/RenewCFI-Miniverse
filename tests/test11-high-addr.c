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
  if( address == 0xe000000e ){
    return true;
  }
  return false;
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	//xor eax,eax;inc eax;mov ecx,0xe00000e;call ecx;inc eax;nop;nop;ret;call 0xa;inc eax;nop;nop;ret
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0e\x00\x00\xe0\xff\xd1\x40\x90\x90\xc3\xe8\xf7\xff\xff\xff\x40\x90\x90\xc3";

	void *code_buffer = (void*)0xe0000000;
	
	mmap(code_buffer, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));
	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 0x2000, PROT_EXEC|PROT_READ);
        uint32_t res = ((uint32_t (*)())code_buffer)();
        printf("Result: %d Expected: 4\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
