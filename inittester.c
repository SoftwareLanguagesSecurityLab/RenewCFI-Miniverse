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

#define REGISTER_HANDLER_OFFSET 0x12b7a0
//#define REGISTER_HANDLER_OFFSET 0x141cdd
#define GEN_CODE_OFFSET 0x1bd
//#define GEN_CODE_OFFSET 0x1671c

// An approximation of start of data section, rounded down to nearest page boundary
#define DATA_OFFSET_START 0x1d1000
//#define DATA_OFFSET_START 0x1e7000
#define DATA_SIZE 0x114ff0
//#define DATA_SIZE 0x114fd0

// An approximation of start of bss section, rounded down to nearest page boundary
#define BSS_OFFSET_START 0x2e5000
//#define BSS_OFFSET_START 0x2fb000
#define BSS_SIZE 0x1af0

/* Map memory for miniverse library and set up handlers. 
   */
void* miniverse_init(){
  struct stat st;
  if( stat("libminiversebin", &st) != 0 ){
    puts("Loading Miniverse library failed.  Stat failure.\n");
    exit(0);
  }
  int fd = open("libminiversebin", O_RDONLY);
  mmap((void*)0xa000000, st.st_size, PROT_EXEC, MAP_PRIVATE, fd, 0);
  close(fd);
  /* Set data section of library to be writable and not executable */
  mprotect((void*)(0xa000000+DATA_OFFSET_START), DATA_SIZE, PROT_WRITE);
  /* Map bss section with zeros */
  //mprotect((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE, PROT_WRITE);
  munmap((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE);
  mmap((void*)(0xa000000+BSS_OFFSET_START), BSS_SIZE, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  void (*register_handler)() = (void (*)())(0xa000000 + REGISTER_HANDLER_OFFSET);
  register_handler();
  return (void*)0x0; /* Do not actually return any pointer, as the handler will call gen_code */
}
