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

/* Simple example of a function prologue to test target alignment */
uint8_t prologue1[] = {"\x55\x89\xe5"}; // push ebp; mov ebp, esp 

bool my_is_target(uintptr_t address, uint8_t *bytes){
//printf("is_target: 0x%x\n", address);
  if( memcmp(prologue1, bytes, 3) == 0 ){
//printf("true: %hhx == %hhx\n", *prologue1, *bytes);
    return true;
  }else if( address == 0x700015c || address == 0x7000162 ){
//printf("true: Special case 1!\n");
    return true; // Special cases for example
  }else if( (address & 0xfff) == 0x68c || (address & 0xfff) == 0x692 ){
//printf("true: Special case 2!\n");
    return true; // Special cases for example so
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
}

#define NUM_CODE_PAGES 10
/* Map varying amounts of memory and copy a tiny function into two places
   within each allocated region.  Then call all the target locations where
   the function was copied. */
void alloc_and_call(){
	uint8_t orig_code[] = "\x8b\x44\x24\x04\xc3";
	void *pages[NUM_CODE_PAGES];
	int i;
	for( i = 0; i < NUM_CODE_PAGES; i++ ){
		pages[i] = mmap(0, 0x1000*(i+1), PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		memcpy(pages[i]+(0x1000*(i/2)), orig_code, sizeof(orig_code));
		memcpy(pages[i]+(0x1000*(i)), orig_code, sizeof(orig_code));
	}
	for( i = 0; i < NUM_CODE_PAGES; i++ ){
		uint32_t result = code_caller(
			(uintptr_t)pages[i]+(0x1000*(i/2)),i);
        	printf("Loop result A: %d\n", result );
		result = code_caller((uintptr_t)pages[i]+(0x1000*i),i);
        	printf("Loop result B: %d\n", result );
	}
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	uint8_t orig_code[] = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\x19\x00\x00\x07\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\x0f\x00\x00\x07\xc3\x90\xeb\xfe\xe9\xff\xff\xff\xfe";
 
	void *code_buffer = (void*)0x7000000;
	
	/* The rewriter chokes at the end of this allocated page because it tries to read full
	   addresses from locations closer than 4 bytes to the end of the page.  Therefore, for
	   now, allocate 2 pages so that only the first page is actually rewritten, but there is
	   a safety buffer to read past the end of the first page.
	   TODO: Handle this edge case */
	mmap(code_buffer, 4096*2, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make our code executable (but only 1st page); our mprotect hook will prevent this */
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

        uint32_t result = code_caller((uintptr_t)code_buffer,0);
        printf("Result for 0: %s (%x)\n", (uint8_t*)result, result );
        result = code_caller((uintptr_t)code_buffer,1);
        printf("Result for 1: %s (%x)\n", (uint8_t*)result, result );

	alloc_and_call();

	return 0;
	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
