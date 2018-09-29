#include "miniverse.h"

int main(int argc, char** argv){
	csh handle;

	uint8_t *origcode = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\xe9\x85\x04\x08\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\xdf\x85\x04\x08\xc3\x90";
	size_t code_size = 36;	// size of @code buffer above
	uint64_t address = 0x80485d0;	// address of first instruction to be disassembled

	uint8_t *finalcode = gen_code(origcode, code_size, address, 16);

	printf("%x\n", *finalcode);

	free(finalcode);
}
