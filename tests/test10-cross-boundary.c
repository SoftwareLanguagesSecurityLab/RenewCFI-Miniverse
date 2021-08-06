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
  //if( address == 0x7001000-8 ) return true;
  return false;
}

void edit_callback(){
  /*
  0000000000000000 40               inc eax                 
  0000000000000001 40               inc eax                 
  0000000000000002 5f               pop edi                 
  0000000000000003 c3               ret
  */
  uint8_t code_patch[] = "\x40\x40\x5f\xc3";

  mprotect((void*)0x7001000,0x1000,PROT_WRITE|PROT_READ);
  memcpy((void*)0x7001001, code_patch, sizeof(code_patch));
  mprotect((void*)0x7001000,0x1000,PROT_EXEC|PROT_READ);
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
        //mmap_hook(&mmap);
        //mprotect_hook(&mprotect);
        register_handler(&my_is_target);

	/* Without the terminating ret instruction, superset disassembly
           trims off the expected sequence, as it concludes that the sequence
	   must not be possible, as it would flow to the end of the region
	   without a jmp or ret.  This assumption clearly could be violated
	   depending on the nature of generated code, as is the case here where
	   the code is edited later in a callback, and the original code was
	   able to flow into invalid instructions without breaking (because the
	   bad instructions were rewritten before they were reached).  This
	   has implications for our ability to trim invalid sequences, because
	   it's theoretically possible for jit code to be generated that falls
	   through into illegal code, and only becomes legal through further
	   edits to the code.  Do jit compilers do such a thing?  I haven't
	   found evidence of that yet, but it's something to keep in mind.
	*/
	/*
	0000000000000000 31c0             xor eax, eax            
	0000000000000002 57               push edi                
	0000000000000003 8d7c2408         lea edi, [esp+0x8]      
	0000000000000007 ff17             call dword [edi]        
	0000000000000009 f4               hlt                     
	000000000000000a f4               hlt                     
	000000000000000b f4               hlt                     
	000000000000000c c3               ret 
	*/
	uint8_t orig_code[] = "\x31\xc0\x57\x8d\x7c\x24\x08\xff\x17\xf4\xf4\xf4\xc3";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer+0x1000-8, orig_code, sizeof(orig_code));
	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 0x2000, PROT_EXEC|PROT_READ);
        uint32_t res = ((uint32_t (*)(uint32_t))code_buffer+0x1000-8)((uint32_t)edit_callback);
        printf("Result: %d Expected: 2\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
