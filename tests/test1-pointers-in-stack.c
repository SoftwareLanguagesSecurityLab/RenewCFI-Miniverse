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
  switch( address ){
    case 0x7000015:
    case 0x700001b:
    case 0x7000024:
    case 0x7000050:
    case 0x7000053:
    case 0x7000056:
      return true;
  }
  return false;
}

int main(int argc, char** argv){

	/* Hooks are currently done with linker flags, not runtime functions */
  //mmap_hook(&mmap);
  //mprotect_hook(&mprotect);
  register_handler(&my_is_target);

	/* 
    I have found a real-world example of an indirect jump instruction
    that references an address in the stack as an offset from the stack
    pointer.  Therefore, I have written this test to provide a variety of
    jmp and call instructions with various encodings that dereference some
    address based on esp.  This includes [esp], [esp+disp8], [esp+disp32],
    [esp+<reg>+disp8], and [esp+<reg>+disp32].  It does not test the limits
    of disp8 to check if a rewriter correctly handles a disp8 that is close
    to overflowing.
	*/
	/*
 0  31 c0                                            xor	eax, eax
 2  68 24 00 00 07                                   push	0x7000024
 7  68 1b 00 00 07                                   push	0x700001b
 c  68 15 00 00 07                                   push	0x7000015
11  ff 24 24                                         jmp	dword ptr [esp]
14  f4                                               hlt
15  40                                               inc	eax
16  ff 64 24 04                                      jmp	dword ptr [esp + 4]
1a  f4                                               hlt
1b  40                                               inc	eax
1c  ff a4 24 08 00 00 00                             jmp	dword ptr [esp + 8]
23  f4                                               hlt
24  83 c4 0c                                         add	esp, 0xc
27  68 50 00 00 07                                   push	0x7000050
2c  68 53 00 00 07                                   push	0x7000053
31  68 56 00 00 07                                   push	0x7000056
36  53                                               push	ebx
37  bb 04 00 00 00                                   mov	ebx, 4
3c  ff 14 1c                                         call	dword ptr [esp + ebx]
3f  ff 54 1c 04                                      call	dword ptr [esp + ebx + 4]
43  ff 94 1c 08 00 00 00                             call	dword ptr [esp + ebx + 8]
4a  5b                                               pop	ebx
4b  83 c4 0c                                         add	esp, 0xc
4e  c3                                               ret
4f  f4                                               hlt
50  40                                               inc	eax
51  c3                                               ret
52  f4                                               hlt
53  40                                               inc	eax
54  c3                                               ret
55  f4                                               hlt
56  40                                               inc	eax
57  c3                                               ret
	*/
	uint8_t orig_code[] = "\x31\xc0\x68\x24\x00\x00\x07\x68\x1b\x00\x00\x07\x68\x15\x00\x00\x07\xff\x24\x24\xf4\x40\xff\x64\x24\x04\xf4\x40\xff\xa4\x24\x08\x00\x00\x00\xf4\x83\xc4\x0c\x68\x50\x00\x00\x07\x68\x53\x00\x00\x07\x68\x56\x00\x00\x07\x53\xbb\x04\x00\x00\x00\xff\x14\x1c\xff\x54\x1c\x04\xff\x94\x1c\x08\x00\x00\x00\x5b\x83\xc4\x0c\xc3\xf4\x40\xc3\xf4\x40\xc3\xf4\x40\xc3";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));
	/* Try to make code executable; our mprotect hook will prevent this */
        mprotect(code_buffer, 0x1000, PROT_EXEC|PROT_READ);
        uint32_t res = ((uint32_t (*)())code_buffer)();
        printf("Result: %d Expected: 5\n", res );

	return 0;

	/* Since this isn't a library loaded in the traditional way, it doesn't have destructors
	   and therefore should execute without crashing */
}
