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
	

	uint8_t *orig_code = (uint8_t *)(addr_start);
	/*size_t code_size = 43;*/	// size of @code buffer above
	size_t code_size = 0x6ff;
	uintptr_t address = (uintptr_t)orig_code;// address of first instruction to be disassembled
	uintptr_t new_address = 0x9000000;	// address of start of generated code
	size_t new_size = 0;

	mmap((void*)new_address, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 

	uint32_t *mapping = gen_code(orig_code, code_size, address,
		new_address, &new_size, 16, &is_target);

	uintptr_t entry;
	/* All calls, even successful ones, will cause a segfault because the
	   destructor for the library will be called at the end of the program, but the execute
	   permissions for the library code have been revoked. */
	/* Fails due to lack of PIC support */
	//uintptr_t entry = 0x5db;// Offset of function we want to execute (get_fstring_c)
        /* Works! */
	//uintptr_t entry = 0x610;// Offset of function we want to execute (get_fstring)
 	/* Fails due to unknown corruption of lookup table entry */
	entry = 0x66c;
	printf("get_msg1: 0x%x\n", mapping[entry]);
	entry = 0x672;
	printf("get_msg2: 0x%x\n", mapping[entry]);
	//entry = 0x633;// Offset of function we want to execute (get_fstring_indirect)
	entry = 0x6d9;// Offset of function we want to execute (print)
	entry = mapping[entry];// Look up new entry point
	free(mapping);

        size_t pages = (new_size/4096)+1;
	/*
	mmap((void*)new_address, 4096*pages, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 
        memcpy((void*)new_address, new_code, new_size);
	free(new_code);*/
        mprotect((void*)new_address, 4096*pages, PROT_EXEC);

        uint32_t result = code_caller(new_address+entry,0);
        printf("Result for 0: %s (%x)\n", (uint8_t*)result, result );
        result = code_caller(new_address+entry,1);
        printf("Result for 1: %s (%x)\n", (uint8_t*)result, result );
	return 0;
}
