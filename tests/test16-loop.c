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
    Execute a selection of loop, loope, and loopne instructions, trying to cover
    various aspects of each instruction
  */
  /*
mov eax,0;mov ecx, 2;looplabel:;inc eax;loop looplabel;jz error;mov ecx,2;loopelabel:;inc eax;loope loopelabel;jz error;mov ecx,2;loopnelabel:;inc eax;loopne loopnelabel;jz error;ret;error:;hlt
  */
  /*
7000000  b8 00 00 00 00                                   mov	eax, 0
7000005  b9 02 00 00 00                                   mov	ecx, 2
700000a  40                                               inc	eax
700000b  e2 fd                                            loop	0x700000a
700000d  74 15                                            je	0x7000024
700000f  b9 02 00 00 00                                   mov	ecx, 2
7000014  40                                               inc	eax
7000015  e1 fd                                            loope	0x7000014
7000017  74 0b                                            je	0x7000024
7000019  b9 02 00 00 00                                   mov	ecx, 2
700001e  40                                               inc	eax
700001f  e0 fd                                            loopne	0x700001e
7000021  74 01                                            je	0x7000024
7000023  c3                                               ret	
7000024  f4                                               hlt
  */
	uint8_t orig_code[] = "\xb8\x00\x00\x00\x00\xb9\x02\x00\x00\x00\x40\xe2\xfd\x74\x15\xb9\x02\x00\x00\x00\x40\xe1\xfd\x74\x0b\xb9\x02\x00\x00\x00\x40\xe0\xfd\x74\x01\xc3\xf4";
  /*
    Do a similar test to the previous, but pushing the 8-bit offset to its
    limits, forcing the rewriter to do something to handle expanding the
    rewritten code size to the point that the 8-bit offset won't work

    Interestingly, keystone v0.9.2 will assemble incorrect loop instructions
    if the target is outside the encodable range.
  */
  /*
  mov eax,0;mov ecx, 2;mov edx,2;looplabel:;inc eax;dec edx;jmp loopjmp;afterloop:;mov ecx,2;loopelabel:;mov edx,1;inc eax;dec edx;jmp loopejmp;afterloope:;mov ecx,4;mov edx,2;loopnelabel:;inc eax;dec edx;jmp loopnejmp;afterloopne:;ret;error:;hlt;nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];nop dword ptr [eax+eax+0x00];loopjmp:;loop looplabel;jnz error;jmp afterloop;loopejmp:;loope loopelabel;jnz error;jmp afterloope;loopnejmp:;loopne loopnelabel;jnz error;jmp afterloopne
  */
  /*
7000000  b8 00 00 00 00                               mov	eax, 0
7000005  b9 02 00 00 00                               mov	ecx, 2
700000a  ba 02 00 00 00                               mov	edx, 2
700000f  40                                           inc	eax
7000010  4a                                           dec	edx
7000011  eb 7a                                        jmp	0x700008d
7000013  b9 02 00 00 00                               mov	ecx, 2
7000018  ba 01 00 00 00                               mov	edx, 1
700001d  40                                           inc	eax
700001e  4a                                           dec	edx
700001f  eb 72                                        jmp	0x7000093
7000021  b9 04 00 00 00                               mov	ecx, 4
7000026  ba 02 00 00 00                               mov	edx, 2
700002b  40                                           inc	eax
700002c  4a                                           dec	edx
700002d  eb 6a                                        jmp	0x7000099
700002f  c3                                           ret
7000030  f4                                           hlt
7000031  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000035  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000039  0f 18 24 00                                  nop	dword ptr [eax + eax]
700003d  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000041  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000045  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000049  0f 18 24 00                                  nop	dword ptr [eax + eax]
700004d  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000051  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000055  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000059  0f 18 24 00                                  nop	dword ptr [eax + eax]
700005d  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000061  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000065  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000069  0f 18 24 00                                  nop	dword ptr [eax + eax]
700006d  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000071  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000075  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000079  0f 18 24 00                                  nop	dword ptr [eax + eax]
700007d  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000081  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000085  0f 18 24 00                                  nop	dword ptr [eax + eax]
7000089  0f 18 24 00                                  nop	dword ptr [eax + eax]
700008d  e2 80                                        loop	0x700000f
700008f  75 9f                                        jne	0x7000030
7000091  eb 80                                        jmp	0x7000013
7000093  e1 83                                        loope	0x7000018
7000095  75 99                                        jne	0x7000030
7000097  eb 88                                        jmp	0x7000021
7000099  e0 90                                        loopne	0x700002b
700009b  75 93                                        jne	0x7000030
700009d  eb 90                                        jmp	0x700002f
  */
  uint8_t orig_code2[] = "\xb8\x00\x00\x00\x00\xb9\x02\x00\x00\x00\xba\x02\x00\x00\x00\x40\x4a\xeb\x7a\xb9\x02\x00\x00\x00\xba\x01\x00\x00\x00\x40\x4a\xeb\x72\xb9\x04\x00\x00\x00\xba\x02\x00\x00\x00\x40\x4a\xeb\x6a\xc3\xf4\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\x0f\x18\x24\x00\xe2\x80\x75\x9f\xeb\x80\xe1\x83\x75\x99\xeb\x88\xe0\x90\x75\x93\xeb\x90";

	void *code_buffer = (void*)0x7000000;
	void *code_buffer2 = (void*)0x7001000;
	
	mmap(code_buffer, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mmap(code_buffer2, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));
	memcpy(code_buffer2, orig_code2, sizeof(orig_code2));
	/* Try to make code executable; our mprotect hook will prevent this */
  mprotect(code_buffer, 0x1000, PROT_EXEC|PROT_READ);
  mprotect(code_buffer2, 0x1000, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer)();
  assert( res == 5 );
  res = ((uint32_t (*)())code_buffer2)();
  assert( res == 6 );

  puts("Ok");
	return 0;
}
