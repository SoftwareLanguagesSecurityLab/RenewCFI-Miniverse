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
    Test various call instructions with segment prefixes.  This does not
    test all prefixes, and it does not test other jump/jcc instructions
    with these prefixes.  If I do ever encounter examples in the wild, then
    those should be added here.

    The ds prefix is not added when trying to assemble (since it's the
    default for the instruction), so I manually added the byte.  Apparently,
    that prefix (3e) has been repurposed for the Intel CET extensions as
    "notrack" to disable a CET feature (Indirect Branch Tracking), but the
    instruction will still execute as expected.  It seems like Intel has
    removed the primary documentation for CET, so I don't know what's up with
    that.  It was surprisingly hard to find.

    This performs the getpid system call via the __kernel_vsyscall function,
    which is stored at gs+0x10, at least on my system.
  */
  /*
  mov eax, 20;call DWORD PTR gs:0x10;xor eax,eax;call DWORD PTR ds:0x700001f; call DWORD PTR cs:0x700001f;ret;inc eax;ret

  + 4 data bytes: 0x1d 0x00 0x00 0x07
  */
  /*
 0  b8 14 00 00 00                           mov	eax, 0x14
 5  65 ff 15 10 00 00 00                     call	dword ptr gs:[0x10]
 c  31 c0                                    xor	eax, eax
 e  3e ff 15 1f 00 00 07                     call	dword ptr ds:[0x700001f]
15  2e ff 15 1f 00 00 07                     call	dword ptr cs:[0x700001f]
1c  c3                                       ret
1d  40                                       inc	eax
1e  c3                                       ret
1f  1d 00 00 07                              (data bytes)
  */
	uint8_t orig_code[] = "\xb8\x14\x00\x00\x00\x65\xff\x15\x10\x00\x00\x00\x31\xc0\x3e\xff\x15\x1f\x00\x00\x07\x2e\xff\x15\x1f\x00\x00\x07\xc3\x40\xc3\x1d\x00\x00\x07";

	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	memcpy(code_buffer, orig_code, sizeof(orig_code));
	/* Try to make code executable; our mprotect hook will prevent this */
  /* Note that the mprotect has a smaller length parameter than the mmap */
  mprotect(code_buffer, 0x1000, PROT_EXEC|PROT_READ);
  uint32_t res = ((uint32_t (*)())code_buffer)();
  assert( res == 2 );

  puts("Ok");
	return 0;
}
