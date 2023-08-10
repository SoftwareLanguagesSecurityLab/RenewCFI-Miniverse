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
  xor eax,eax;inc eax;mov ecx, 0x700000b;jmp ecx;hlt;inc eax;ret
  */
  /*
7000000  31 c0                                            xor	eax, eax
7000002  40                                               inc	eax
7000003  b9 0b 00 00 07                                   mov	ecx, 0x700000b
7000008  ff e1                                            jmp	ecx
700000a  f4                                               hlt
700000b  40                                               inc	eax
700000c  c3                                               ret
  */
	uint8_t orig_code[] = "\x31\xc0\x40\xb9\x0b\x00\x00\x07\xff\xe1\xf4\x40\xc3";
  /*
    Create a snippet of jit code at an address far from the other jit code
  */
  /*
  xor eax,eax;inc eax;mov ecx, 0xf600000b;jmp ecx;hlt;inc eax;ret
  */
  /*
f6000000  31 c0                                            xor	eax, eax
f6000002  40                                               inc	eax
f6000003  b9 0b 00 00 f6                                   mov	ecx, 0xf600000b
f6000008  ff e1                                            jmp	ecx
f600000a  f4                                               hlt
f600000b  40                                               inc	eax
f600000c  c3                                               ret
  */
  uint8_t orig_code2[] = "\x31\xc0\x40\xb9\x0b\x00\x00\xf6\xff\xe1\xf4\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	void *code_buffer2 = (void*)0xf6000000;
	
	mmap(code_buffer, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mmap(code_buffer2, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));
	memcpy(code_buffer2, orig_code2, sizeof(orig_code2));
	/* Try to make code executable; our mprotect hook will prevent this */
  mprotect(code_buffer, 0x1000, PROT_EXEC|PROT_READ);
  mprotect(code_buffer2, 0x1000, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer)();
  assert( res == 2 );
  res = ((uint32_t (*)())code_buffer2)();
  assert( res == 2 );

  puts("Ok");
	return 0;
}
