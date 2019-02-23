#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "inittester.h"

void patch_binary(void* address, size_t size, void* libaddress, size_t libsize){
  (void)address;
  (void)size;
  (void)libaddress;
  (void)libsize;
  /* Get program phdrs */
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
    mapped_size = load_binary(fd, (void*)0xa000000);
    close(fd);

    if( stat(argv[1], &st) != 0 ){
      printf("Loading %s failed.  Stat failure.\n", argv[1]);
      exit(0);
    }
    fd = open(argv[1], O_RDONLY);
    bin_addr = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    patch_binary(bin_addr,st.st_size, (void*)0xa000000, mapped_size);
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
