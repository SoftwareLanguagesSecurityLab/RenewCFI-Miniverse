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
#include <unistd.h>

#include <assert.h>
#include <errno.h>

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

extern void load_miniverse_asm();

void load_miniverse_simple(){

  int fd = open("standalone", O_RDONLY);
  
  if( fd < 0 ){
    abort();
  }

  /* These addresses will vary if miniverse is altered at all,
   * and will need to be changed */
  /* Code segment */
  /* (length is starting offset plus memory size of third program header) */
  uint8_t *mini_exec = mmap((void*)0xdeadb000, 0xa0aab, PROT_READ|PROT_EXEC,
                            MAP_PRIVATE,fd,0);
  if( mini_exec != (uint8_t*)0xdeadb000 ){
    abort();
  }

  /* data segment */
  /* (base address is virtual addr of 4th program header rounded down to the
   * nearest page, and length is enough to cover that + the DYNAMIC segment) */
  uint8_t *mini_data = mmap((void*)0xdeb7c000, 0x15000, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE,fd,0xa0000);
  if( mini_data != (uint8_t*)0xdeb7c000 ){
    abort();
  }

  /* Clear bss section */
  /* Starting offset is the base address of the data segment + FileSiz */
  /* Length is the ending address of data segment - starting addr of memset */
  memset((void*)0xdeb8ce78, 0, 0x4188);

  //bool* miniverse_lock = (bool*)0xdeb9c868;
  //*miniverse_lock = false;

  /* Set pointer to register_handler function */
  void (*register_handler)(bool (*)(uintptr_t, uint8_t *,uintptr_t, size_t));
  register_handler = (void(*)(bool(*)(uintptr_t,uint8_t*,uintptr_t,size_t)))0xdeae5374;
  register_handler(&my_is_target);

  close(fd);
  
}

void load_miniverse(){

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

  /* These addresses will vary if miniverse is altered at all,
   * and will need to be changed */
  /* Code segment */
  /* (length is starting offset plus memory size of third program header) */
  uint8_t *mini_exec = mmap((void*)0xdeadb000, 0xa0aab, PROT_READ|PROT_EXEC,
                            MAP_PRIVATE,fd,0);
  if( mini_exec != (uint8_t*)0xdeadb000 ){
    fprintf( stderr, "Error %d: Could not mmap executable miniverse region.\n", errno );
    abort();
  }
  

  /* data segment */
  /* (base address is virtual addr of 4th program header rounded down to the
   * nearest page, and length is enough to cover that + the DYNAMIC segment) */
  uint8_t *mini_data = mmap((void*)0xdeb7c000, 0x15000, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE,fd,0xa0000);
  if( mini_data != (uint8_t*)0xdeb8d000 ){
    fprintf( stderr, "Error %d: Could not mmap miniverse data region.\n", errno );
    abort();
  }

  /* Clear bss section */
  /* Starting offset is the base address of the data segment + FileSiz */
  /* Length is the ending address of data segment - starting addr of memset */
  memset((void*)0xdeb8ce78, 0, 0x4188);

  //bool* miniverse_lock = (bool*)0xdeb9c868;
  //*miniverse_lock = false;

  /* Set pointer to register_handler function */
  void (*register_handler)(bool (*)(uintptr_t, uint8_t *,uintptr_t, size_t));
  register_handler = (void(*)(bool(*)(uintptr_t,uint8_t*,uintptr_t,size_t)))0xdeae5374;
  register_handler(&my_is_target);
  
}

int main(int argc, char** argv){

  load_miniverse_asm();
  //load_miniverse_simple();

  /* Set pointer to wrap_mmap function */
  void (*wrap_mmap)(void*,size_t,int,int,int,off_t);
  wrap_mmap = (void(*)(void*,size_t,int,int,int,off_t))0xdeae544b;

  /* Set pointer to wrap_mprotect function */
  void (*wrap_mprotect)(void*,size_t,int);
  wrap_mprotect = (void(*)(void*,size_t,int))0xdeae5521;

  uint8_t orig_code[] = "\x8b\x44\x24\x04\x83\xf8\x00\x74\x14\xb8\x19\x00\x00\x07\xc3\x6d\x6f\x64\x65\x3a\x20\x25\x64\x0a\x00\x25\x73\x0a\x00\xb8\x0f\x00\x00\x07\xc3\x90\xeb\xfe\xe9\xff\xff\xff\xfe";
 
  void *code_buffer = (void*)0x7000000;
	
  wrap_mmap(code_buffer, 4096*2, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
  memcpy(code_buffer, orig_code, sizeof(orig_code));

  wrap_mprotect(code_buffer, 4096, PROT_EXEC|PROT_READ);

  uint32_t result = ((uint32_t (*)(uint32_t))code_buffer)(0);
  printf("Result for 0: %s (%x)\n", (uint8_t*)result, result );
  result = ((uint32_t (*)(uint32_t))code_buffer)(1);
  printf("Result for 1: %s (%x)\n", (uint8_t*)result, result );
  return 0;

}
