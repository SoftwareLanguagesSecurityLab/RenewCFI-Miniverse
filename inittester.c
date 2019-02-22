/* This library provides the initialization for libminiversebin, which
   is supposed to be loaded into the address space of an arbitrary binary
   without cooperation.  This is performing the tasks that should eventually
   be inserted into the original binary by the static rewriter, including:
     -Loading the library into the address space of the original binary,
      probably statically (but here we dynamically load it to make sure it
      doesn't need any patching by the dynamic loader and is therefore
      completely standalone
     -Installing the interrupt handler and screening calls to mmap and mprotect.
      This will allow us to hijack calls to generated code.  In case there
      are multiple calls to the original code, we should handle both calls to
      non-rewritten code and rewritten code in our handlers.  In a fully
      statically rewritten binary, the original generated code should probably
      only be called into once, because once we patch the generated code, the
      rewritten binary's indirect jumps  will notice that the target isn't 0x90
      and automatically look up our rewritten code.  However, in case of stale
      callbacks or something we should have this safety mechanism anyway, and
      it will be needed for a binary that isn't fully rewritten such as the
      binaries we will generate with this initialization library.
   However, for now this code can just be linked into a test binary to evaluate
   the ability of the library to perform rewriting of code generated at runtime.
   */
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <errno.h>

#define REGISTER_HANDLER_OFFSET 0x92fc
//#define REGISTER_HANDLER_OFFSET 0x140803
//#define REGISTER_HANDLER_OFFSET 0x1407bd
//#define REGISTER_HANDLER_OFFSET 0x12b7a0
//#define REGISTER_HANDLER_OFFSET 0x141cdd
//#define GEN_CODE_OFFSET 0x1bd
//#define GEN_CODE_OFFSET 0x1671c

// An approximation of start of data section, rounded down to nearest page boundary
//#define DATA_OFFSET_START 0x1d1000
#define DATA_OFFSET_START 0x15000
//#define DATA_OFFSET_START 0x1e7000
//#define DATA_SIZE 0x114ff0
#define DATA_SIZE 0xd000
//#define DATA_SIZE 0x114fd0

// An approximation of start of bss section, rounded down to nearest page boundary
// This contains fields that normally may be initialized behind the scenes,
// but will not be initialized since we're just dropping this in.  Something
// to investigate is __sysinfo, which appears to hold the address of pointers
// in the vdso or something.  It appears that __vsyscall in musl reads from
// __sysinfo-some_offset to get the code to perform a fast syscall, but if it
// finds 0 instead it will use the safe slower fallback of using the int
// instruction.  This is what I believe was happening when I was testing earlier
// because syscalls were working fine previously, but after having the data/bss
// sections get...misaligned(?) (another thing to investigate), the value at
// the offset was filled with garbage, causing __vsyscall to call some random
// address and crash.
//#define BSS_OFFSET_START 0x2e5000
#define BSS_OFFSET_START 0x21000
//#define BSS_OFFSET_START 0x2fb000
#define BSS_SIZE 0x2000
//#define BSS_SIZE 0x1b04
//#define BSS_SIZE 0x1af0

/* Iterate through relocation entries, assuming they only consist of
   type R_386_RELATIVE as we attempt to compile the binary ahead of
   time to not contain any other types of relocations. */
void patch_relocs(Elf32_Rel* reloc, size_t count, void* address){
  size_t i;
  for( i = 0; i < count; i++){
    if( reloc->r_info == R_386_RELATIVE ){
      /* Add base address to value at address of relocation entry */
      *(uint32_t*)((uintptr_t)address + reloc->r_offset) += (uintptr_t)address;
    }else{
      puts("Only R_386_RELATIVE relocations supported.  Abort.");
      exit(0);
    }
    reloc++;
  }
}

/* Load binary at address specified.  Assume address is not NULL and that
   we can guarantee that there is enough space at the specified address to
   map the binary into memory without colliding with another mapped region */
void load_binary(int fd, void* address){
  Elf32_Ehdr* ehdr;
  Elf32_Phdr* phdr;
  Elf32_Shdr* shdr;
  uintptr_t seg_addr,align_offset;
  //void* ehdr_addr;
  void* shdr_addr;
  int i;
  /* Map elf header into memory */
  ehdr = (Elf32_Ehdr*)mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
  /* Read phdr offset from ELF header */
  printf("phdr offset: %d\n", ehdr->e_phoff);
  phdr = (Elf32_Phdr*)((uintptr_t)ehdr+ehdr->e_phoff);
  /* Iterate through phdr entries to find LOAD segments */
  for( i = 0; i < ehdr->e_phnum; i++ ){
    if( phdr->p_type == PT_LOAD ){
      printf("Load offset: 0x%x addr: 0x%x\n", phdr->p_offset, phdr->p_vaddr );
      /* Load segment at correct address relative to load address */
      seg_addr = ((uintptr_t)address+phdr->p_vaddr) & 0xfffff000;
      align_offset = ((uintptr_t)address+phdr->p_vaddr) & 0x00000fff;
      mmap((void*)(seg_addr), phdr->p_memsz+align_offset,
        (phdr->p_flags & PF_X) ? PROT_EXEC : PROT_READ|PROT_WRITE,
        MAP_PRIVATE, fd, phdr->p_offset-align_offset );
    }
    phdr++;
  }
  /* Map section header table into memory (assume it doesn't exceed a page)
     Unfortunately we can't map from a non-page-aligned offset, so we have to
     map some of the file contents before the section header table. */
  shdr_addr = (Elf32_Shdr*)mmap(0, 0x1000, PROT_READ, MAP_PRIVATE,
    fd, ehdr->e_shoff & 0xfffff000);
  shdr = (Elf32_Shdr*)((uintptr_t)shdr_addr+(ehdr->e_shoff & 0x00000fff));
  printf( "error result: %d, %s\n", errno, strerror( errno ));
  for( i = 0; i < ehdr->e_shnum; i++ ){
    /* Assume that section of type SHT_NOBITS is .bss section, use address and
       size to zero out bits in this region, overwriting garbage content
       from sections following .bss */
    if( shdr->sh_type == SHT_NOBITS ){
      memset( address+shdr->sh_addr, 0, shdr->sh_size);
    }else if( shdr->sh_type == SHT_REL ){
      /* Retrieve section with relocation entries.  For x86, it is of type
         SHT_REL, whereas for x86-64 it is SHT_RELA */
      patch_relocs( (Elf32_Rel*)(address+shdr->sh_offset),
        (size_t)((shdr->sh_size)/sizeof(Elf32_Rel)), address );
    }
    shdr++;
  }
  munmap(shdr_addr, 0x1000);
  munmap(ehdr, 0x1000);
}

/* Map memory for miniverse library and set up handlers. 
   */
void* miniverse_init(){
  struct stat st;
  if( stat("libminiversebin", &st) != 0 ){
    puts("Loading Miniverse library failed.  Stat failure.\n");
    exit(0);
  }
  int fd = open("libminiversebin", O_RDONLY);
  load_binary(fd, (void*)0xa000000);
  //mmap((void*)0xa000000, st.st_size, PROT_EXEC, MAP_PRIVATE, fd, 0);
  close(fd);
  /* Set data section of library to be writable and not executable */
  //mprotect((void*)(0xa000000+DATA_OFFSET_START), DATA_SIZE, PROT_WRITE);
  /* Map bss section with zeros */
  //mprotect((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE, PROT_WRITE);
  //munmap((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE);
  //mmap((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  void (*register_handler)() = (void (*)())(0xa000000 + REGISTER_HANDLER_OFFSET);
  register_handler();
  return (void*)0x0; /* Do not actually return any pointer, as the handler will call gen_code */
}
