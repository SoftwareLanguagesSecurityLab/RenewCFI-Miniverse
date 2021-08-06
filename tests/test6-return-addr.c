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
  return false;
}

void introspect_callback(uintptr_t addr){
  printf("Address: 0x%x\n", *(&addr-1) );
  assert( *(&addr-1) == 0x700000a );
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);


	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 40               inc eax                 
	0000000000000003 ff542404         call dword [esp+0x4]    
	0000000000000007 40               inc eax                 
	0000000000000008 90               nop                     
	0000000000000009 90               nop                     
	000000000000000a c3               ret
	*/
	//uint8_t orig_code[] = "\x31\xc0\x40\xff\x54\x24\x04\x40\x90\x90\xc3";

	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 40               inc eax                 
	0000000000000003 8b1542404        mov edx, [esp]          
	0000000000000007 50               push eax
	0000000000000008 ffd2             call edx                
	000000000000000a 58               pop eax
	000000000000000b 40               inc eax                 
	000000000000000c 90               nop                     
	000000000000000d c3               ret
	*/
	uint8_t orig_code[] = "\x31\xc0\x40\x8b\x54\x24\x04\x50\xff\xd2\x58\x40\x90\xc3";
 
	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

	// No need to call code_caller if I use the .s preprocessing script!
	// That script automatically aligns the indirect call instruction that
	// this line generates, so that the return address for the instruction
	// after this call is aligned!
        uint32_t res = ((uint32_t (*)(uint32_t))code_buffer)((uint32_t)introspect_callback);
        printf("Result: %d Expected: 2\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
