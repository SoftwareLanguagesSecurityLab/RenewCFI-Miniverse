/* Test prototype for segfault handler and mmap hooks
   when supporting libraries are linked in at compile time and mmap
   hooks are handled by linker flags,
   and the only code generated is a small, simple byte string copied
   into a new memory region at runtime.

   Test case for when a call instruction is also a target 
*/

#include "miniverse.h"
#include "inittester.h"
#include "handlers.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

//#include <signal.h>
//#include <inttypes.h>
//#include <stdbool.h>

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
  if( address == 0x700000e ){
    printf("true: Special case 1!\n");
    return true; // Special cases for example
  }
  return false;
}

void* funcarr[] = {(void*)0x7000000,(void*)0x7000000};
uintptr_t pointer_offset = 0;

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	//xor eax,eax;inc eax;mov ecx,0x700000e;call ecx;inc eax;nop;nop;ret;call 0xa;inc eax;nop;nop;ret
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0e\x00\x00\x07\xff\xd1\x40\x90\x90\xc3\xe8\xf7\xff\xff\xff\x40\x90\x90\xc3";
 
	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

	// No need to call code_caller if I use the .s preprocessing script!
	// That script automatically aligns the indirect call instruction that
	// this line generates, so that the return address for the instruction
	// after this call is aligned!
        uint32_t res = ((uint32_t (*)())code_buffer)();
        printf("Result: %d Expected: 4\n", res );
	// It turned out that putting the function pointer in an array
	// and calling it that way didn't end up generating a different kind
        // of call instruction.  I ended up resorting to hand-written assembly
	// to mimic the kind of instructions I am encountering.
	// Therefore, here I have inline assembly that calls the first entry in
	// funcarr by using its offset from the GOT.  This produces a longer
	// call instruction than a simple "call [eax]" instruction.
	// Offset of zero
	//void* ptr = (void*)((uint8_t*)funcarr);
	asm( //"movl %0, %%edx;"
	     "call piclabel\npiclabel:\n\t"
	     "pop %%eax\n\t"
	     "addl $_GLOBAL_OFFSET_TABLE_,%%eax\n\t"
	     "inc %%eax\n\t"
	     "call *funcarr@GOTOFF(%%eax)\n\t"
	     "mov %%eax, %0"
	     : "=r"(res)  /* output */
	     : /* input */
	     : "%eax", "%ecx", "%edx" /* clobbered */
	);
        printf("Result: %d Expected: 4\n", res );
	// Offset of 4 (one pointer over)
	/*void* ptr = (void*)((uint8_t*)funcarr-0x100);
	asm( //"movl %0, %%edx;"
	     "call *0x104(%1)\n\t"
	     "mov %%eax, %0"
	     : "=r"(res)  // output
	     : "r"(ptr) // input
	     : "%eax", "%ecx", "%edx" //
	);
        printf("Result: %d Expected: 4\n", res );*/

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
