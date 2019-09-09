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

bool my_is_target(uintptr_t address, uint8_t *bytes){
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
	0000000000000002 50               push eax                
	0000000000000003 40               inc eax                 
	0000000000000004 e804000000       call 0xd                
	0000000000000009 90               nop                     
	000000000000000a 90               nop                     
	000000000000000b 40               inc eax                 
	000000000000000c c3               ret                     
	000000000000000d 90               nop                     
	000000000000000e 90               nop                     
	000000000000000f 40               inc eax                 
	0000000000000010 c20400           ret 0x4 
	*/
	uint8_t orig_code[] = "\x31\xc0\x50\x40\xe8\x04\x00\x00\x00\x90\x90\x40\xc3\x90\x90\x40\xc2\x04\x00";

	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 81ec00010000     sub esp, 0x100          
	0000000000000008 40               inc eax                 
	0000000000000009 e80d000000       call 0x1b
	000000000000000e 81ec00020000     sub esp, 0x200          
	0000000000000014 e806000000       call 0x1f
	0000000000000019 40               inc eax                 
	000000000000001a c3               ret                     
	000000000000001b 40               inc eax                 
	000000000000001c c20001           ret 0x100               
	000000000000001f 40               inc eax                 
	0000000000000020 c20002           ret 0x200
	*/
	uint8_t orig_code2[] = "\x31\xc0\x81\xec\x00\x01\x00\x00\x40\xe8\x0d\x00\x00\x00\x81\xec\x00\x02\x00\x00\xe8\x06\x00\x00\x00\x40\xc3\x40\xc2\x00\x01\x40\xc2\x00\x02";
 
	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));

	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

	// No need to call code_caller if I use the .s preprocessing script!
	// That script automatically aligns the indirect call instruction that
	// this line generates, so that the return address for the instruction
	// after this call is aligned!
        uint32_t res = ((uint32_t (*)(uint32_t))code_buffer)(0);
        printf("Result: %d Expected: 3\n", res );
        mprotect(code_buffer, 4096, PROT_WRITE|PROT_READ);
	memcpy(code_buffer, orig_code2, sizeof(orig_code2));
        mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);
        res = ((uint32_t (*)(uint32_t))code_buffer)(0);
        printf("Result: %d Expected: 4\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
