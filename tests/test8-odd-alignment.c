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

uint8_t nop_offset = 0;
uint8_t nops[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

bool my_is_target(uintptr_t address, uint8_t *bytes){
  if( address == 0x7000009+nop_offset ) return true;
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

	/* Offset varies depending on inserted nops */
	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 ba09000007       mov edx, 0x7000009      
	0000000000000007 ffe2             jmp edx                 
	0000000000000009 40               inc eax                 
	000000000000000a c3               ret
	*/
	uint8_t orig_code[] = "\x31\xc0\xba\x09\x00\x00\x07\xff\xe2\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);



	// No need to call code_caller if I use the .s preprocessing script!
	// That script automatically aligns the indirect call instruction that
	// this line generates, so that the return address for the instruction
	// after this call is aligned!
        for( nop_offset = 0; nop_offset < 16; nop_offset++ ){
          mprotect(code_buffer, 4096, PROT_WRITE|PROT_READ);
          memcpy(code_buffer, nops, nop_offset);
          orig_code[3] = 0x09 + nop_offset; /* Patch jmp destination */
	  memcpy(code_buffer+nop_offset, orig_code, sizeof(orig_code));
	  /* Try to make code executable; our mprotect hook will prevent this */
          mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);
          uint32_t res = ((uint32_t (*)(uint32_t))code_buffer)(0);
          printf("Result: %d Expected: 1\n", res );
        }

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
