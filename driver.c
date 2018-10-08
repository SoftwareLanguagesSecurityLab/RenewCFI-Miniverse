#include "miniverse.h"
#include <sys/mman.h>
#include <string.h>

bool is_target(uint64_t address, uint8_t *bytes){
  return false;
}

int main(int argc, char** argv){
	csh handle;

	uint8_t *orig_code = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\xe9\x85\x04\x08\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\xdf\x85\x04\x08\xc3\x90\xeb\xfe\xe9\xff\xff\xff\xfe";
	size_t code_size = 43;	// size of @code buffer above
	uint64_t address = 0x80485d0;	// address of first instruction to be disassembled
	uint32_t new_address = 0x9000000;	// address of start of generated code
	size_t new_size = 0;

	uint8_t *new_code = gen_code(orig_code, code_size, address,
		(uint64_t)new_address, &new_size, 16, &is_target);

        size_t pages = (new_size/4096)+1;
	mmap((void*)new_address, 4096*pages, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 
        memcpy((void*)new_address, new_code, new_size);
	free(new_code);
        mprotect((void*)new_address, 4096*pages, PROT_EXEC);

        uint32_t result = ((uint32_t (*)(uint32_t))new_address)(0);
        printf("Result for 0: %x\n", result);
        result = ((uint32_t (*)(uint32_t))new_address)(1);
        printf("Result for 1: %x\n", result);
}
