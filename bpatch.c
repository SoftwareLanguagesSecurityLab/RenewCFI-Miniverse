#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "inittester.h"

#define LIB_ADDRESS 0xa000000

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

/* Load in assembled entry point code */
/* Copy backup of original entry point code */
/* Patch parameters to mmap, addresses of miniverse library & entry point */
/* Drop entry point code on top of original entry point */
void patch_entry(void* entry_address, void* lib_address, size_t lib_size,
    void* lib_entry/*, void* entry_backup*/){
  int fd;
  void *new_entry, *entry_copy;
  size_t offset;
  struct mmap_arg_struct* mmap_arg = 0;
  uintptr_t *patch_addr;
  fd = open("entry", O_RDONLY);
  new_entry = mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  
  /* Back up page starting with entry point */
  entry_copy = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
printf( "error result: %d, %s\n", errno, strerror( errno ));  
  memcpy(entry_copy, entry_address, 0x1000);

  /* Copy over original entry point with our new entry point */
  memcpy(entry_address, new_entry, 0x1000);
  for( offset = 0; offset < 0x1000; offset++ ){
    /* mmap argument for entry point code is tagged with four 0xf4 bytes */
    if( *(uint32_t*)(entry_address+offset) == 0xf4f4f4f4 ){
      mmap_arg = (struct mmap_arg_struct*)(entry_address+offset);
      break;
    }
  }
  if( mmap_arg == 0 ){
    puts("ERROR: invalid entry point assembly. Aborting.");
    exit(0);
  }
  /* Populate arguments for mapping in library */
  mmap_arg->addr = (unsigned long)lib_address;
  mmap_arg->len = lib_size;
  mmap_arg->prot = PROT_READ | PROT_EXEC | PROT_WRITE;
  mmap_arg->flags = MAP_PRIVATE;
  mmap_arg->fd = -1;
  mmap_arg->offset = 0;
  
  /* Set the locations of library entry and backed up entry point */
  patch_addr = (uintptr_t*)(mmap_arg+1);
  *patch_addr++ = (uintptr_t)lib_entry;
  //*patch_addr = (uintptr_t)entry_backup;
}

void patch_binary(void* address/*, size_t size*/,
    void* lib_address, size_t lib_size, void* lib_entry){
  Elf32_Ehdr* ehdr;
  Elf32_Phdr* phdr; 
  Elf32_Addr entry;
  void* entry_address;
  /* Get program phdrs */
  ehdr = (Elf32_Ehdr*)address;
  phdr = (Elf32_Phdr*)(address+ehdr->e_phoff);
  entry = ehdr->e_entry;
  /* TODO: A malformed binary could cause us to overread the phdr table
     although a malformed binary could also give a wrong number of phdrs, so
     it might not be something to worry about */
  while( phdr->p_type != PT_LOAD ){
    phdr++;
  }
  if( phdr->p_offset != 0 ){
    puts("Error: expected first PT_LOAD segment to have 0 offset. Aborting.");
    exit(0);
  }
  entry_address = address+(entry-phdr->p_vaddr);
  /* For now, don't bother with figuring out where the backup is */
  patch_entry(entry_address, lib_address, lib_size, lib_entry/*, (void*)0*/);
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
  size_t mapped_lib_size;
  size_t mapped_bin_size;
  struct stat st;
  void* bin_addr;
  char* outfname;
  int outfname_size;
  void* lib_entry;
  if( argc == 2 ){
    fd = open("libminiversebin", O_RDONLY);
    /* Load and patch library in memory, which we will later add to binary */
    /* TODO: This should be called load_library, my code is getting messy
       because I am having trouble keeping track of everything I need to
       patch/load */
    mapped_lib_size = load_library(fd, (void*)LIB_ADDRESS, &lib_entry);
    close(fd);
    if( stat(argv[1], &st) != 0 ){
      printf("Loading %s failed.  Stat failure.\n", argv[1]);
      exit(0);
    }

    /* Dump library's binary image as it is laid out in memory to a file. */
    fd = open("libminiverseflat", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    write(fd, (void*)LIB_ADDRESS, mapped_lib_size);
    close(fd);

    fd = open(argv[1], O_RDONLY);    
    mapped_bin_size = st.st_size + mapped_lib_size;
    mapped_bin_size += (0x1000 - mapped_bin_size % 0x1000) + 0x1000;
    /* Map memory containing binary image plus extra space for
       page containing entry point backup bytes, just in case there's no space
       in the file after the last segment; when the file is first mapped
       this extra space will be zeroes, but we will patch in the entry point
       backup before we output the modified binary. */
    bin_addr = mmap(0, mapped_bin_size,
      PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    /* Pass the actual binary size for now; if it's needed, we will expand the
       binary to hold that extra data. */
    patch_binary(bin_addr/*,st.st_size*/, (void*)LIB_ADDRESS,
      mapped_lib_size, lib_entry);
    outfname_size = strlen(argv[1]);
    outfname = malloc(outfname_size + 3);
    strcpy(outfname, argv[1]);
    outfname[outfname_size] = '-';
    outfname[outfname_size+1] = 'r';
    outfname[outfname_size+2] = '\0';
    fd = open(outfname, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
    /* TODO: We are writing the exact size of the original binary.  We may
       continue to do so if we do not try expanding the last segment */
    if( write(fd, bin_addr, st.st_size) != st.st_size ){
      puts("WARNING: Write did not successfully write all bytes to file.\n");
    }
    close(fd);
  }else{
    printf("Usage: %s <file>\n", argv[0]);
  }
  return 0;
}
