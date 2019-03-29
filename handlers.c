/* This file contains:
     -Shim functions intended to interpose on mmap and mprotect, prohibiting
      the W+X combination of permissions and instead passing a request
      for only W.  This allows the pages to be written to but not executed.
     -An interrupt handler for SIGSEGV, only for handling when a page marked
      W (by our previous functions?) is attempting to be executed.  This
      triggers the rewriter and redirects the original call from the writable
      page to the new rewritten executable page.  It also should set the
      original writable page to only be readable, I think....
*/
#include <sys/mman.h>
#include <signal.h>
#include "handlers.h"

#include "miniverse.h"
 
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <sys/ucontext.h> // For hardware-specific registers (TODO: Does not work as expected!)

typedef struct {
  uintptr_t	address;
  size_t	size;
  bool		rewritten;
  uintptr_t	new_address;
  uint32_t*	mapping;
} code_region_t;

size_t num_code_regions = 0;
pa_entry_t code_regions_mem = {NULL,0};

/* Try to add a new region that the program is attempting to set as executable.
   If it is already present, we just set rewritten to be false again.
   Right now, we only add regions, as we would need to hook munmap to know if
   a memory region has been removed. */
void add_code_region(uintptr_t address, size_t size){
  size_t i;
  code_region_t* region;
  if( code_regions_mem.address == NULL ){
    /* TODO: flexibly allocate more pages as needed.  For now, ASSUME we only
       need one page to hold data on all code regions */
    page_alloc(&code_regions_mem, 0x1000);
    printf("Allocated code regions at 0x%x\n", (uintptr_t)code_regions_mem.address);
  }
  region = code_regions_mem.address;
  /* Iterate through all known regions.  If a matching region is already
     present, set its rewritten status to false and return. */
  for( i = 0; i < num_code_regions; i++ ){
    if( region->address == address && region->size == size ){
      region->rewritten = false;
      return;
    }
    region++;
  }
  /* If we made it here, the region was new, so save it. */
  region->address = address;
  region->size = size;
  region->rewritten = false;
  region->mapping = 0;
  num_code_regions++;
}

/* Attempt to retrieve a region that the program attempted to set as executable.
   Returns false if the region is not present (should indicate an actual
   segfault), otherwise populates region argument.
   This lookup is performed only using the address, as we will only have the 
   faulting address for a segfault, not the size of a region. */
bool get_code_region(code_region_t** region, uintptr_t address){
  size_t i;
  *region = code_regions_mem.address;
  for( i = 0; i < num_code_regions; i++ ){
    if( (*region)->address <= address &&
        (*region)->address + (*region)->size > address ){
      return true;
    }
    (*region)++;
  }
  return false;
}

void *__real_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);

int __real_mprotect(void *addr, size_t len, int prot);

/* TODO: Actually insert hooks that redirect calls to mmap and mprotect
   For now we can actually rely on the dynamic loader to hook the functions
   for us.  When we link, we replace references to the symbol with our wrappers.
   Perhaps we could use L_PRELOAD at runtime, or our static rewriter.  Regardless,
   the simplest hook for now shouldn't need these.  */
void mmap_hook(void *addr){
  (void)(addr);
  //mmap_real = mmap;
}

void mprotect_hook(void *addr){
  (void)(addr);
  //mprotect_real = mprotect;
}

void register_handler(){
  struct sigaction new_action, old_action;
  /* Use sa_sigaction instead of sa_handler */
  new_action.sa_handler = NULL;
  void* sig_handler = &sigsegv_handler;
  new_action.sa_sigaction = sig_handler;
  sigemptyset(&new_action.sa_mask); /* Don't block other signals */
  new_action.sa_flags = SA_SIGINFO; /* Specifies we want to use sa_sigaction */
  sigaction( SIGSEGV, &new_action, &old_action );
}

/* Create wrapper for printf that performs a no-op to try
   and test whether removing calls to printf solves our problem */
int __wrap_printf(const char * format, ...){
  (void)(format);
  return 0; // Perform no-op instead of printing something
}

/* TODO: consider never allowing setting the exec bit under any
   condition, as we don't want an application under our control to
   ever load any new executable code without it going through our
   rewriting process first. */
/* TODO: Check that the call to __real_mmap actually succeeds before assuming
   that the memory is actually going to be allocated; otherwise, someone could
   fool the rewriter into rewriting an arbitrary memory region. */
void *__wrap_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset){
  printf("(mmap) ADDR: 0x%x PROT_EXEC: %d !PROT_EXEC: %d prot: %d\n", (uintptr_t)addr, PROT_EXEC, ~PROT_EXEC, prot);
  if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
    prot &= ~PROT_EXEC; /* Unset the exec bit */
    add_code_region((uintptr_t)addr, length); 
  }
  return __real_mmap(addr,length,prot,flags,fd,offset);
}

/* Prevent any page from dynamically being allowed to have exec permissions
   added, and if any other permissions are added we also want to remove exec
   privileges too.  TODO: Handle the same chunk of memory repeatedly having
   permissions changed, even after we may have rewritten it before */
int __wrap_mprotect(void *addr, size_t len, int prot){
  printf("(mprotect) ADDR: 0x%x PROT_EXEC: %d !PROT_EXEC: %d prot: %d\n", (uintptr_t)addr, PROT_EXEC, ~PROT_EXEC, prot);
  if( (prot & PROT_EXEC) ){
    /* Always unset the exec bit if set */
    prot &= ~PROT_EXEC;
    /* Also unset the write bit so we will detect attempts to change already
       rewritten code TODO: detect attempts to switch from exec to writable */
    prot &= ~PROT_WRITE;
    add_code_region((uintptr_t)addr, len); 
  }
  return __real_mprotect(addr,len,prot);
}

/*   TODO: Not thread safe? */
//uintptr_t new_address = 0x0000000;// address of start of generated code; let kernel decide where
// Allocate a larger size than the rewriter thinks, in order to reserve enough space to accommodate
// our expanded rewritten code. TODO: Handle this in a less hackish way
#define NEW_ALLOC_SAFETY 4
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext){
  (void)(sig);
  (void)(info);
  //info->si_addr = (void*)( (uintptr_t)(&mmap_hook) + 5 ); /* Try setting return target to a ret */
  ucontext_t *con = (ucontext_t*)ucontext;
  /* Machine-dependent definition of processor state: set new value for eip */
  /* TODO: Figure out how to refer to REG_EIP rather than this magic number 14 */
  /* Retrieve the address of the instruction pointer.  If the address is in
     a region that needs rewriting, rewrite it. */
  uintptr_t target = con->uc_mcontext.gregs[14];
  code_region_t* region;
  
  /* Check whether instruction pointer is in a known code region (a region we
     know we need to rewrite because we encountered it in an mmap or mprotect
     call).  If not, then the segfault must have been triggered by some actual
     invalid memory access, so abort. */
  if( !get_code_region(&region, target) ){
    abort();
  }

  printf( "Stats for region @ 0x%x: 0x%x, %d, %d, 0x%x, 0x%x\n", (uintptr_t)region, region->address, region->size, region->rewritten, region->new_address, (uintptr_t)region->mapping);
  /* If region has not been rewritten yet, rewrite it. */
  if( !region->rewritten ){

    /* TODO: Check if mapping is a NULL pointer or not.  If not, that means we
       have already rewritten this region before and need to free the mapping
       first before rewriting it again, as it must have been modified.
       Alternatively, if we set the original region to read-only after
       rewriting, detect attempts to write to it and free the mapping then. */
  
    uint8_t *orig_code = (uint8_t *)(region->address);
    size_t code_size = region->size;
    pa_entry_t new_mem;

    /* Set original code to be readable and writable, regardless of what it was set to before,
       so we may disassemble it and write to it.
       TODO: Set as read-only afterwards to detect changes */
    __real_mprotect((void*)orig_code, code_size, PROT_READ|PROT_WRITE);
  
    page_alloc(&new_mem, code_size/**NEW_ALLOC_SAFETY*/);
  
    region->mapping = gen_code(orig_code, code_size, region->address,
        (uintptr_t*)&new_mem.address, &new_mem.size, 16, &is_target);

    region->new_address = (uintptr_t)new_mem.address;
  
    /* Don't free the mapping because we will need it for subsequent calls!  Do we have to keep
       ALL mappings for all rewritten code regions always allocated so we can look up the target in
       the handler? */
    //free(mapping);
  
    size_t pages = (new_mem.size/0x1000);
  
    printf("Calling real mprotect for exec: 0x%x, 0x%x\n", region->new_address, 0x1000*pages);
    /* Call the real, un-wrapped mprotect to actually set these pages as executable */
    __real_mprotect((void*)region->new_address, 0x1000*pages, PROT_EXEC);

    region->rewritten = true;
  }

  /* TODO: Refer to REG_EIP without a magic number */
  /* Set instruction pointer to corresponding target in rewritten code */;
  con->uc_mcontext.gregs[14] =
      (uintptr_t)(region->new_address+region->mapping[target-region->address]);
}
