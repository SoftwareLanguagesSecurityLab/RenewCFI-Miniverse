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

void *(*mmap_real)(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);

int (*mprotect_real)(void *addr, size_t len, int prot);

/* TODO: Actually insert hooks that redirect calls to mmap and mprotect */
void mmap_hook(void *addr){
  mmap_real = mmap;
}

void mprotect_hook(void *addr){
  mprotect_real = mprotect;
}

void register_handler(){
  struct sigaction new_action, old_action;
  new_action.sa_handler = sigsegv_handler;
  sigemptyset(&new_action.sa_mask); /* Don't block other signals */
  new_action.sa_flags = 0;
  sigaction( SIGSEGV, &new_action, &old_action );
}

/* TODO: consider never allowing setting the exec bit under any
   condition, as we don't want an application under our control to
   ever load any new executable code without it going through our
   rewriting process first. */
void *mmap_shim(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset){
  if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
    prot &= !PROT_EXEC; /* Unset the exec bit */
  }
  mmap_real(addr,length,prot,flags,fd,offset);
}

/* Prevent any page from dynamically being allowed to have exec permissions
   added, and if any other permissions are added we also want to remove exec
   privileges too.  TODO: Handle the same chunk of memory repeatedly having
   permissions changed, even after we may have rewritten it before */
int mprotect_shim(void *addr, size_t len, int prot){
  //if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
    prot &= !PROT_EXEC; /* Unconditionally unset the exec bit */
  //}
  mprotect_real(addr,len,prot);
}

/* TODO: Keep track of which pages we have already dealt with previously,
   as we only need to rewrite the contents once UNLESS further changes are
   made, so we need to know if a page is "dirty" or not. */
void sigsegv_handler(int signum){
  
}
