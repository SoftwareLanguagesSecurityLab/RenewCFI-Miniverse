/*
Test loading in miniverse as a standalone binary blob
*/

#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <assert.h>

/* Simple example of a function prologue to test target alignment */
uint8_t prologue1[] = {"\x55\x89\xe5"}; // push ebp; mov ebp, esp 

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
//printf("is_target: 0x%x\n", address);
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

int main(int argc, char** argv){

  int fd = open("standalone", O_RDONLY);
  
  if( fd < 0 ){
    fprintf( stderr, "Error: Could not find standalone miniverse file.\n" );
    abort();
  }

  struct stat stats;
  int err = fstat(fd, &stats);
  if( fd < 0 ){
    fprintf( stderr, "Error: Could not stat standalone miniverse file.\n" );
    abort();
  }

  /* These addresses may vary if miniverse is altered at all */
  uint8_t *mini_exec = mmap((void*)0xdeadb000, 0xa6554, PROT_READ|PROT_EXEC,
                            MAP_SHARED,fd,0);
  if( mini_exec != (uint8_t*)0xdeadb000 ){
    fprintf( stderr, "Error: Could not mmap executable miniverse region.\n" );
    abort();
  }
  

  /* 0xdeadb000 + 0xa6680 = 0xdeb81680 */
  /* 0x105d0 */
  uint8_t *mini_data = mmap((void*)0xdeb81680, 0xf898, PROT_READ|PROT_WRITE,
                            MAP_SHARED,fd,0xa6680);
  if( mini_data != (uint8_t*)0xdeb81680 ){
    fprintf( stderr, "Error: Could not mmap miniverse data region.\n" );
    abort();
  }

  //register_handler(&my_is_target);

	uint8_t orig_code[] = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\x19\x00\x00\x07\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\x0f\x00\x00\x07\xc3\x90\xeb\xfe\xe9\xff\xff\xff\xfe";
 
	void *code_buffer = (void*)0x7000000;
	
	mmap(code_buffer, 4096*2, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
	memcpy(code_buffer, orig_code, sizeof(orig_code));

  mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

  uint32_t result = ((uint32_t (*)(uint32_t))code_buffer)(0);
  printf("Result for 0: %s (%x)\n", (uint8_t*)result, result );
  result = ((uint32_t (*)(uint32_t))code_buffer)(1);
  printf("Result for 1: %s (%x)\n", (uint8_t*)result, result );
	return 0;

}
