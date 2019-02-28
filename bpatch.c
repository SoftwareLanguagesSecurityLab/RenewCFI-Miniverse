#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "inittester.h"

#define LIB_ADDRESS 0xa000000

void entry_restorer(){
  /* Load in assembled entry point code */
  /* Patch parameters to mmap, addresses of miniverse library & entry point */
  /* Drop entry point code on top of original entry point */
}

void patch_binary(void* address, size_t size, void* libaddress, size_t libsize){
  (void)address;
  (void)size;
  (void)libaddress;
  (void)libsize;
  /* Get program phdrs */
  /* TODO: If phdrs include PT_INTERP we need to make sure that isn't altered */
  /* What if it's possible to set a new PHDR location with PT_PHDR */
  /* Copy chunk of code segment as large as current phdrs + 2 extra:
       -One for the copied code itself
       -One for libminiversebin and code segment restoration function */
  /* Patch entry point to point to code segment restoration function */
  /* Return new size for expanded binary */
}

int main(int argc, char** argv){
  int fd;
  size_t mapped_size;
  struct stat st;
  void* bin_addr;
  if( argc == 2 ){
    fd = open("libminiversebin", O_RDONLY);
    /* Load and patch binary in memory, which we will later add to binary */
    mapped_size = load_binary(fd, (void*)LIB_ADDRESS);
    close(fd);

    if( stat(argv[1], &st) != 0 ){
      printf("Loading %s failed.  Stat failure.\n", argv[1]);
      exit(0);
    }
    fd = open(argv[1], O_RDONLY);
    bin_addr = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    patch_binary(bin_addr,st.st_size, (void*)LIB_ADDRESS, mapped_size);
    /*fd = open(argv[1], O_WRONLY);
    if( write(fd, bin_addr, st.st_size) != st.st_size ){
      puts("WARNING: Write did not successfully write all bytes to file.\n");
    }
    close(fd);*/
  }else{
    printf("Usage: %s <file>\n", argv[0]);
  }
  return 0;
}
