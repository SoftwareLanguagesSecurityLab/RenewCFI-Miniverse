/* Test direct calls, jumps, and returns across regions
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
  /* Act as if every address is a target, which expands the rewritten code
     size substantially */
  return true;
}

int main(int argc, char** argv){

  register_handler(&my_is_target);

  /* 
    Create a snippet of jit code that will be run at one address
  */
  /*
  xor eax,eax;inc eax;mov ecx, 0x7000f0b;jmp ecx;hlt;inc eax;ret
  */
  /*
7000f00  31 c0                                            xor	eax, eax
7000f02  40                                               inc	eax
7000f03  b9 0b 0f 00 07                                   mov	ecx, 0x7000f0b
7000f08  ff e1                                            jmp	ecx
7000f0a  f4                                               hlt
7000f0b  40                                               inc	eax
7000f0c  c3                                               ret
  */
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0b\x0f\x00\x07\xff\xe1\xf4\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 0xf0c, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer+0xf00, orig_code, sizeof(orig_code));
	/* Try to make code executable; our mprotect hook will prevent this */
  /* Note that the mprotect has a smaller length parameter than the mmap */
  mprotect(code_buffer, 0xf0a, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer+0xf00)();
  assert( res == 2 );

  puts("Ok");
	return 0;
}
