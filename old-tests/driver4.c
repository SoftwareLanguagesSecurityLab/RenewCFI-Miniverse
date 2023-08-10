#include "miniverse.h"
#include "inittester.h"
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

char* get_fstring(int index);
char* get_fstring_indirect(int index);
//char* get_fstring_c(int index);
char* print(int index);

/* Simple example of a function prologue to test target alignment */
uint8_t prologue1[] = {"\x55\x89\xe5"}; // push ebp; mov ebp, esp 

bool is_target(uintptr_t address, uint8_t *bytes){
printf("is_target: 0x%x\n", address);
  if( memcmp(prologue1, bytes, 3) == 0 ){
printf("true: %hhx == %hhx\n", *prologue1, *bytes);
    return true;
  }else if( address == 0x700015c || address == 0x7000162 ){
printf("true: Special case 1!\n");
    return true; // Special cases for example
  }else if( (address & 0xfff) == 0x68c || (address & 0xfff) == 0x692 ){
printf("true: Special case 2!\n");
    return true; // Special cases for example so
  }
  return false;
}

/* Try to get call instruction aligned right */
uint32_t __attribute__((aligned(16))) code_caller(uintptr_t addr, int arg){
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  __asm__ volatile("nop");
  ((uint32_t (*)(uint32_t))addr)(arg);
}

int main(int argc, char** argv){
	csh handle;

        uint32_t* (*gen_code)(const uint8_t*, size_t, uintptr_t, uintptr_t, size_t*, uint8_t, bool (*)(uintptr_t, uint8_t *));
        gen_code = ( uint32_t* (*)(const uint8_t*, size_t, uintptr_t, uintptr_t, size_t*, uint8_t, bool (*)(uintptr_t, uint8_t *)) ) miniverse_init();
	/* Printing address of function in library, because otherwise the library
	   will not be loaded. */
	printf("0x%x\n", (uintptr_t)&print);
	/* Getting the address of a function in a library unfortunately
	   returns the address of its plt entry, which is not what we want.
	   In order to get the address of the code I want to rewrite, I will use
	   /proc/self/maps instead. */
	char* line;
        char* line_off;
        size_t line_len = 0;
	uintptr_t addr_start;
	FILE* f = fopen("/proc/self/maps","r");
	while( true ){
		getline( &line, &line_len, f);
		if( strstr( line, "libtest" ) ) break;
	}
	// Only get here if we found libtest mapped in memory.
	// Now line contains address of libtest text section
	line_off = strchr( line, '-');
	*line_off = '\0';
	sscanf(line, "%x", &addr_start);	
	
	/* Make library non-executable */
        mprotect((void*)addr_start, 4096, PROT_READ);

        uint32_t result = code_caller((uintptr_t)print,0);
        printf("Result for 0: %s (%x)\n", (uint8_t*)result, result );
        result = code_caller((uintptr_t)print,1);
        printf("Result for 1: %s (%x)\n", (uint8_t*)result, result );
	return 0;

	/* Execution will end in a segfault because the
	   destructor for the library will be called at the end of the program, but the execute
	   permissions for the library code have been revoked. */
}
