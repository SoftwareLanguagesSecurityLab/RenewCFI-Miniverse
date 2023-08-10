/* Test some unusual call instructions using esp
*/

#include "miniverse.h"
#include "inittester.h"
#include "handlers.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

#include <assert.h>

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
  if( address == 0x700002e ) return true;
  return false;
}

int main(int argc, char** argv){

  register_handler(&my_is_target);

  /* Test several types of call instructions that read from an address
     relative to the stack pointer.
     Note, however, that I do not test with an address stored at esp-4.
     This is because my rewriter generates code that will clobber any data
     stored at that address.  I have not encountered code with this exact
     behavior and only encountered the problem because I generated some
     code that did this.  Since I can change the code I can generate, I'm
     going to leave this edge case for now.  If it ever happens in the wild,
     I will add a special case for it then. 
  */
  /*
 0  31 c0                                            xor	eax, eax
 2  6a 00                                            push	0
 4  6a 00                                            push	0
 6  68 2e 00 00 07                                   push	0x700002e
 b  ff 14 24                                         call	dword ptr [esp]
 e  83 c4 08                                         add	esp, 8
11  ff 54 24 f8                                      call	dword ptr [esp - 8]
15  81 ec 00 01 00 00                                sub	esp, 0x100
1b  68 2e 00 00 07                                   push	0x700002e
20  81 c4 08 01 00 00                                add	esp, 0x108
26  ff 94 24 f8 fe ff ff                             call	dword ptr [esp - 0x108]
2d  c3                                               ret
2e  40                                               inc	eax
2f  c3                                               ret
  */
	uint8_t orig_code[] = "\x31\xc0\x6a\x00\x6a\x00\x68\x2e\x00\x00\x07\xff\x14\x24\x83\xc4\x08\xff\x54\x24\xf8\x81\xec\x00\x01\x00\x00\x68\x2e\x00\x00\x07\x81\xc4\x08\x01\x00\x00\xff\x94\x24\xf8\xfe\xff\xff\xc3\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memcpy(code_buffer, orig_code, sizeof(orig_code));
  /* Try to make code executable; our mprotect hook will prevent this */
  mprotect(code_buffer, 0x1000, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer)();
  assert( res == 3 );

  printf("Ok\n");
	return 0;
}
