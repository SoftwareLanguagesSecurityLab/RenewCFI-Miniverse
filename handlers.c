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

void *__real_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);

int __real_mprotect(void *addr, size_t len, int prot);

/* TODO: Actually insert hooks that redirect calls to mmap and mprotect
   For now we can actually rely on the dynamic loader to hook the functions
   for us.  When we link, we replace references to the symbol with our wrappers.
   Perhaps we could use L_PRELOAD at runtime, or our static rewriter.  Regardless,
   the simplest hook for now shouldn't need these.  */
void mmap_hook(void *addr){
  //mmap_real = mmap;
}

void mprotect_hook(void *addr){
  //mprotect_real = mprotect;
}

void register_handler(){
  struct sigaction new_action, old_action;
  /* Use sa_sigaction instead of sa_handler */
  new_action.sa_sigaction = sigsegv_handler;
  sigemptyset(&new_action.sa_mask); /* Don't block other signals */
  new_action.sa_flags = SA_SIGINFO; /* Specifies we want to use sa_sigaction */
  sigaction( SIGSEGV, &new_action, &old_action );
}

/* TODO: consider never allowing setting the exec bit under any
   condition, as we don't want an application under our control to
   ever load any new executable code without it going through our
   rewriting process first. */
void *__wrap_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset){
  printf("(mmap) PROT_EXEC: %d !PROT_EXEC: %d prot: %d\n", PROT_EXEC, ~PROT_EXEC, prot);
  if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
    prot &= ~PROT_EXEC; /* Unset the exec bit */
  }
  __real_mmap(addr,length,prot,flags,fd,offset);
}

/* Prevent any page from dynamically being allowed to have exec permissions
   added, and if any other permissions are added we also want to remove exec
   privileges too.  TODO: Handle the same chunk of memory repeatedly having
   permissions changed, even after we may have rewritten it before */
int __wrap_mprotect(void *addr, size_t len, int prot){
  printf("(mprotect) PROT_EXEC: %d !PROT_EXEC: %d prot: %d\n", PROT_EXEC, ~PROT_EXEC, prot);
  //if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
    prot &= ~PROT_EXEC; /* Unconditionally unset the exec bit */
  //}
  __real_mprotect(addr,len,prot);
}

/* Temporary hack to prevent rewriting twice; if we don't do this, doing mmap on an already allocated
   new code area doesn't seem to change the permissions, so it stays executable.  We eventually will
   only want to rewrite again if changes were made to the original pages, and we would want to unmap
   the old rewritten code in that case anyway.
   TODO: Not thread safe, doesn't handle multiple code regions, etc, etc. */
bool already_rewritten = false;
uint32_t *mapping = 0;
/* TODO: Keep track of which pages we have already dealt with previously,
   as we only need to rewrite the contents once UNLESS further changes are
   made, so we need to know if a page is "dirty" or not.
   Right now, just always try to rewrite the page our target is on, and NOT a
   remembered region from previous calls to mprotect or mmap, as we maybe
   should eventually do. */
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext){
  //info->si_addr = (void*)( (uintptr_t)(&mmap_hook) + 5 ); /* Try setting return target to a ret */
  ucontext_t *con = (ucontext_t*)ucontext;
  /* Machine-dependent definition of processor state: set new value for eip */
  /* TODO: Figure out how to refer to REG_EIP rather than this magic number 14 */
  /* Set target to a ret instruction, just for testing.  Next, we will redirect
     this to the rewritten entry point of the code. */
  uintptr_t target = con->uc_mcontext.gregs[14];
  uintptr_t address = (uintptr_t)(target - (target % 0x1000)); // addr of 1st inst to be disassembled
  uintptr_t new_address = 0x9000000;      // address of start of generated code

  if( !already_rewritten ){
  
    uint8_t *orig_code = (uint8_t *)(target - (target % 0x1000));
    size_t code_size = 0x1000;
    size_t new_size = 0;

    /* Set original code to be readable and writable, regardless of what it was set to before,
       so we may disassemble it and write to it.
       TODO: Set as read-only afterwards to detect changes */
    __real_mprotect((void*)orig_code, 4096, PROT_READ|PROT_WRITE);
  
    mmap((void*)new_address, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  
    mapping = gen_code(orig_code, code_size, address, new_address,
        &new_size, 16, &is_target);
  
    /* Don't free the mapping because we will need it for subsequent calls!  Do we have to keep
       ALL mappings for all rewritten code regions always allocated so we can look up the target in
       the handler? */
    //free(mapping);
  
    size_t pages = (new_size/4096)+1;
  
    /* Call the real, un-wrapped mprotect to actually set these pages as executable */
    __real_mprotect((void*)new_address, 4096*pages, PROT_EXEC);

    already_rewritten = true;
  }

  /* TODO: Refer to REG_EIP without a magic number */
  /* Set instruction pointer to corresponding target in rewritten code */;
  con->uc_mcontext.gregs[14] = (uintptr_t)(new_address + mapping[target-address]);
}
