/* Test prototype for segfault handler and mmap hooks
   when supporting libraries are linked in at compile time and mmap
   hooks are handled by linker flags,
   and the only code generated is a small, simple byte string copied
   into a new memory region at runtime.
*/

#include "miniverse.h"
#include "inittester.h"
#include "handlers.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

bool my_is_target(uintptr_t address, uint8_t *bytes){
  if( address == 0x700000e ){
    printf("true: Special case 1!\n");
    return true; // Special cases for example
  }
  return false;
}

/* Try to get call instruction aligned right */
uint32_t __attribute__((aligned(16))) code_caller(uintptr_t addr, int arg){
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  ((uint32_t (*)(uint32_t))addr)(arg);
  __asm__ volatile("fwait"); /* TODO MASK: Restore original masking code */
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	//xor eax,eax;inc eax;mov ecx,0x700000e;call ecx;inc eax;ret;nop;nop;inc eax;push 0x700000a;ret
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0e\x00\x00\x07\xff\xd1\x40\xc3\x90\x90\x40\x68\x0a\x00\x00\x07\xc3";
	//inc eax;inc eax;push 0x700000a;ret
	uint8_t orig_code_patch[] = "\x40\x40\x68\x0a\x00\x00\x07\xc3";
	//xor eax,eax;push 0x700000a;ret
	uint8_t orig_code_patch2[] = "\x31\xc0\x68\x0a\x00\x00\x07\xc3";
 
	void *code_buffer = (void*)0x7000000;
	
	/* The rewriter chokes at the end of this allocated page because it tries to read full
	   addresses from locations closer than 4 bytes to the end of the page.  Therefore, for
	   now, allocate 2 pages so that only the first page is actually rewritten, but there is
	   a safety buffer to read past the end of the first page.
	   TODO: Handle this edge case */
	mmap(code_buffer, 4096*2, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 4096*2, PROT_EXEC|PROT_READ);

	// Test code, which involves an indirect jump and weird ret behavior
        uint32_t result = code_caller((uintptr_t)code_buffer,0);
        printf("Result: %d Expected: 4\n", result );

	// Test modifying only part of original code
        mprotect(code_buffer, 4096*2, PROT_WRITE|PROT_READ);
	memcpy(code_buffer+0xe,orig_code_patch,sizeof(orig_code_patch));
        mprotect(code_buffer, 4096*2, PROT_EXEC|PROT_READ);
        result = code_caller((uintptr_t)code_buffer,1);
        printf("Result: %d Expected: 5\n", result );

	// Test modifying a sub-region of the original code and returning
	// cross-region
        mprotect(code_buffer+4096, 4096, PROT_WRITE|PROT_READ);
	memcpy(code_buffer+4096,orig_code_patch2,sizeof(orig_code_patch2));
        mprotect(code_buffer+4096, 4096, PROT_EXEC|PROT_READ);
        result = code_caller((uintptr_t)code_buffer+4096,2);
        printf("Result: %d Expected: 1\n", result );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
