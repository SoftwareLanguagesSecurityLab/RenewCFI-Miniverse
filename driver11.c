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

//#include <signal.h>
//#include <inttypes.h>
//#include <stdbool.h>

bool my_is_target(uintptr_t address, uint8_t *bytes){
  if( address == 0x700000a ){
    printf("true: Special case 1!\n");
    return true; // Special cases for example
  }
  return false;
}

uint32_t pointer_array[] = {0x0000000,0x7000022};

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 40               inc eax                 
	0000000000000003 b90a000007       mov ecx, 0x700000a      
	0000000000000008 ffe1             jmp ecx                 
	000000000000000a 8b4c2404         mov ecx, [esp+0x4]      
	000000000000000e ff5104           call dword [ecx+0x4]    
	0000000000000011 ff9104000000     call dword [ecx+0x4]    
	0000000000000017 ff542104         call dword [ecx+0x4]    
	000000000000001b ff942104000000   call dword [ecx+0x4]    
	0000000000000022 40               inc eax                 
	0000000000000023 90               nop                     
	0000000000000024 90               nop                     
	0000000000000025 c3               ret
	*/
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0a\x00\x00\x07\xff\xe1\x8b\x4c\x24\x04\xff\x51\x04\xff\x91\x04\x00\x00\x00\xff\x54\x21\x04\xff\x94\x21\x04\x00\x00\x00\x40\x90\x90\xc3";
 
	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

	// No need to call code_caller if I use the .s preprocessing script!
	// That script automatically aligns the indirect call instruction that
	// this line generates, so that the return address for the instruction
	// after this call is aligned!
        uint32_t res = ((uint32_t (*)(uint32_t))code_buffer)((uint32_t)pointer_array);
        printf("Result: %d Expected: 6\n", res );
	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
