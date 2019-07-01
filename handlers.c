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
//#define DEBUG
#include <sys/mman.h>
#include <signal.h>
#include "handlers.h"

#include "miniverse.h"
 
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <sys/ucontext.h> // For hardware-specific registers (TODO: Does not work as expected!)

bool default_is_target(uintptr_t address, uint8_t *bytes){
  /* Suppress unused parameter warnings */
  (void)(address);
  (void)(bytes);
  return false;
}

bool (*is_target)(uintptr_t address, uint8_t *bytes) = &default_is_target;

typedef struct {
  uintptr_t	address;
  size_t	size;
  bool		rewritten;
  uintptr_t	new_address;
  size_t	new_size;
  pa_entry_t	backup; /* Backup copy of original bytes */
  pa_entry_t	mapping;
} code_region_t;

void rewrite_region(code_region_t* region);

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
#ifdef DEBUG
    printf("Allocated code regions at 0x%x\n", (uintptr_t)code_regions_mem.address);
#endif
  }
  region = code_regions_mem.address;
  /* Iterate through all known regions.  If a matching region is already
     present, set its rewritten status to false and return.
     If specified size is bigger than the existing region, just expand it. */
  for( i = 0; i < num_code_regions; i++ ){
    if( region->address == address && region->size <= size ){
      region->size = size;
      if( region->rewritten ){
#ifdef DEBUG
        printf("Update code region 0x%x\n", (uintptr_t)region->address);
#endif
        region->rewritten = false;
      }
      return;
    }else if( address > region->address &&
              address < region->address+region->size){
      /* If a new region falls within an existing region, split it
         and omit the new region from that existing region.
         If instead the new region extends to the end of the old region
         or beyond the end, just shorten the old region. */
      if( address+size < region->address+region->size ){
        /* TODO: Handle splitting regions */
        printf("FATAL ERROR: Splitting regions unimplemented!\n");
        abort();
      }else{
        region->size = address - region->address;
      }
    }
    region++;
  }
  /* If we made it here, the region was new, so save it. */
  region->address = address;
  region->size = size;
  region->rewritten = false;
  region->new_address = 0;
  region->new_size = 0;
  region->backup.address = 0;
  region->backup.size = 0;
  region->mapping.address = 0;
  region->mapping.size = 0;
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

void register_handler(bool (*my_is_target)(uintptr_t address, uint8_t *bytes)){
  struct sigaction new_action, old_action;
  if( my_is_target != NULL ){
    is_target = my_is_target;
  }
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
  if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
#ifdef DEBUG
    printf("(mmap) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif
    prot &= ~PROT_EXEC; /* Unset the exec bit */
    /* Get actual address, in case mmap is passed 0 for the address */
    void* real_addr = __real_mmap(addr,length,prot,flags,fd,offset);
    /* Verify mmap succeeded before adding code region */
    if( real_addr != MAP_FAILED ){
      add_code_region((uintptr_t)real_addr, length);
    } 
    return real_addr;
  }
  return __real_mmap(addr,length,prot,flags,fd,offset);
}

/* Prevent any page from dynamically being allowed to have exec permissions
   added, and if any other permissions are added we also want to remove exec
   privileges too.  TODO: Handle the same chunk of memory repeatedly having
   permissions changed, even after we may have rewritten it before */
int __wrap_mprotect(void *addr, size_t len, int prot){
  code_region_t* region;
#ifdef DEBUG
  printf("(mprotect) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif
  if( (prot & PROT_EXEC) ){
#ifdef DEBUG
  printf("(mprotect YES) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif
    add_code_region((uintptr_t)addr, len); 
    /* Always unset the exec bit if set */
    prot &= ~PROT_EXEC;
    if( (prot & PROT_WRITE) ){
      /* Also unset the write bit so we will detect attempts to change already
         rewritten code TODO: detect attempts to switch from exec to writable */
      prot &= ~PROT_WRITE;
    }else{
      /* If write is NOT set, then let's try rewriting this region immediately
         since we know the code is done writing to it for now.  Trying to
         proactively rewrite a region might cause some issues, but it also will
         partially address the issue of rewritten code attempting to indirect
         call into un-rewritten code.  This doesn't fix the issue for RWX code,
         but for generated code with good hygiene it should work. */
      get_code_region(&region, (uintptr_t)addr);
#ifdef DEBUG
      printf("Rewriting 0x%x (size 0x%x) early!\n", region->address, region->size);
#endif
      rewrite_region(region);
      /* Indicate success; permissions for region are now RW regardless of
         original arguments to mprotect intending to make it non-writable */
      return 0;
    }
  }else if( (prot & PROT_WRITE) && get_code_region(&region,(uintptr_t)addr) ){
#ifdef DEBUG
    printf("Detected present region 0x%x (mprotect addr 0x%x) -> writable!\n", region->address, (uintptr_t)addr);
    printf("Copying from %x to %x, %x bytes!\n", (uintptr_t)((uintptr_t)region->backup.address+(addr-region->address)), (uintptr_t)addr, len);
#endif
    /* If the code is being set to writable but not executable,
       AND if the address is in an existing region,
       restore original bytes to the region before program can write to it */
    int result = __real_mprotect(addr,len,prot); /* Set writable first */
    /* Restore the bytes for full region or whichever sub-region has been
       set writable; after this sub-region is set back to executable it
       will be split into a separate region when we attempt to rewrite it. */
    memcpy(addr,(void*)((uintptr_t)region->backup.address+(addr-region->address)),len);
    return result;
  }
  return __real_mprotect(addr,len,prot);
}

void rewrite_region(code_region_t* region){

  /* TODO: Determine if it is EVER safe to free a mapping or rewritten code,
     as we may always have stale pointers floating around. */

  uint8_t *orig_code = (uint8_t *)(region->address);
  size_t code_size = region->size;
  size_t i;
  uint32_t offset;
  pa_entry_t new_mem;
  pa_entry_t old_mapping;
  pa_entry_t backup_mem;

#ifdef DEBUG
  printf("Calling real mprotect for orig: 0x%x, 0x%x\n", (uintptr_t)orig_code, code_size);
#endif
  /* Set original code to be readable and writable,
     regardless of what it was set to before,
     so we may disassemble it and write to it.
     TODO: Set as read-only afterwards to detect changes */
  __real_mprotect((void*)orig_code, code_size, PROT_READ|PROT_WRITE);

  old_mapping = region->mapping;

  page_alloc(&new_mem, code_size);

  /* Free old backup if one is present */
  if( region->backup.address != 0 ){
#ifdef DEBUG
    printf("Free old backup: 0x%x, len 0x%x\n", (uintptr_t)region->backup.address, region->backup.size);
#endif
    backup_mem.address = region->backup.address;
    backup_mem.size = region->backup.size;
    page_free(&backup_mem);
  }
  /* Backup original bytes before rewriting and patching old code section */
  page_alloc(&backup_mem, code_size);
  memcpy(backup_mem.address, orig_code, code_size);
  region->backup = backup_mem;

  region->mapping = gen_code(orig_code, code_size, region->address,
      (uintptr_t*)&new_mem.address, &new_mem.size, 16, is_target);

  /* Patch old code, since after rewriting, it is out of date.
     TODO: There may be stale pointers into the old rewritten code, so this
     probably cannot actually be freed safely.  However, let's try doing
     this anyway, because those stale pointers into the old rewritten code
     might also fail, since they would be pointing to stale code.  It would
     be better to have an obvious, immediate segfault than have wrong code
     run.  If I find code that fails due to trying to jump to unmapped code
     that was previously rewritten, then I can fix it then. */
  if( region->new_address != 0 ){
#ifdef DEBUG
    printf("Patch old rewritten code: 0x%x (len 0x%x)\n", region->new_address, region->new_size);
#endif
    __real_mprotect((void*)region->new_address, region->new_size, PROT_READ|PROT_WRITE);
    for( i = 0; i < old_mapping.size/4; i++ ){
      offset = *((uint32_t*)old_mapping.address+i);
#ifdef DEBUG
      if( offset >= region->new_size ){
        printf("WARNING: Too large offset 0x%x\n", offset);
      }
#endif
      if( offset < region->new_size && offset % 16 == 0 && i < region->mapping.size/4){
        /* Patch in address at target in old rewritten code with the true
           destination in the new rewritten code, which we REALLY HOPE is also
           aligned.  OR with 0x3 to indicate a valid entry, will be masked */
        *((uint32_t*)region->new_address+offset/4) = \
            (*((uint32_t*)region->mapping.address+i)+(uint32_t)new_mem.address)|0x3;
      }
    }
    /* Free old mapping, which must have been present if we got here */
    page_free(&old_mapping);
    //page_free(&new_mem);
  }

  region->new_address = (uintptr_t)new_mem.address;
  region->new_size = (uintptr_t)new_mem.size;

  size_t pages = (new_mem.size/0x1000);

#ifdef DEBUG
  printf("Calling real mprotect for exec: 0x%x, 0x%x\n", region->new_address, 0x1000*pages);
#endif

  /* Call the real, un-wrapped mprotect to actually set these pages
     as executable */
  __real_mprotect((void*)region->new_address, 0x1000*pages, PROT_EXEC);

#ifdef DEBUG
  printf("Region 0x%x is rewritten\n", region->address);
#endif
  region->rewritten = true;
}

/* TODO: refer to REG_EIP using a system header rather than this define */
#define REG_EIP 14
/* Catch all segfaults here and detect attempts to execute generated code
   so that we can rewrite it or redirect it to existing rewritten code. */
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext){
  (void)(sig);
  (void)(info);
  ucontext_t *con = (ucontext_t*)ucontext;
  /* Retrieve the address of the instruction pointer.  If the address is in
     a region that needs rewriting, rewrite it. */
  uintptr_t target = con->uc_mcontext.gregs[REG_EIP];
  code_region_t* region;
  
  /* Check whether instruction pointer is in a known code region (a region we
     know we need to rewrite because we encountered it in an mmap or mprotect
     call).  If not, then the segfault must have been triggered by some actual
     invalid memory access, so abort. */
  if( !get_code_region(&region, target) ){
#ifdef DEBUG
    printf("WARNING: 0x%x is untracked, attempting lookup.\n", target);
#endif
    if( *((uint32_t*)target) & 0x3 ){
      /* Set instruction pointer to masked target lookup */;
      con->uc_mcontext.gregs[REG_EIP] =
          (uintptr_t)(*((uint32_t*)target) & 0xfffffff0);
      return;
    }else{
      printf("FATAL ERROR: 0x%x never encountered in mmap/mprotect!\n", target);
      abort();
    }
  }
  //printf( "Stats for region @ 0x%x: 0x%x, %d, %d, 0x%x, 0x%x\n", (uintptr_t)region, region->address, region->size, region->rewritten, region->new_address, (uintptr_t)region->mapping.address);
  /* If region has not been rewritten yet, rewrite it. */
  if( !region->rewritten ){
    rewrite_region(region);
  }

  /* Set instruction pointer to corresponding target in rewritten code */;
  con->uc_mcontext.gregs[REG_EIP] =
      (uintptr_t)(region->new_address+((uint32_t*)region->mapping.address)[target-region->address]);
}
