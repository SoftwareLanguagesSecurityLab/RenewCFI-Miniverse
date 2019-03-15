#include "miniverse.h"
#include "handlers.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int __real_mprotect(void *addr, size_t len, int prot);

/* TODO: I may want to name this function miniverse_init */
void miniverse_entry(const char* entry_fname, uintptr_t entry_address){
  int fd;
  printf("Hello: 0x%x, %s\n", entry_address, entry_fname);
  /* Restore original entry point */
  fd = open(entry_fname, O_RDONLY);
  __real_mprotect((void*)(entry_address&0xfffff000), 0x1000, PROT_READ|PROT_WRITE);
  read(fd, (void*)entry_address, 0x1000);
  __real_mprotect((void*)(entry_address&0xfffff000), 0x1000, PROT_READ|PROT_EXEC); 
  /* This function needs to return to the original entry point of the host
     binary, and therefore we must do the stack cleanup and remove the caller's
     arguments.  This assembly uses the address of the entry_address argument
     to find the last argument from the caller (deepest in the stack) and a
     hidden argument after it containing the saved value of edx, which holds
     the address of _dl_fini, which is called on program exit and is specified
     by the System V i386 ABI to be edx. This restores edx, sets ebp to 0 to be
     safe (the deepest stack frame should have ebp set to 0), shifts the stack
     pointer to point 4 bytes below the original stack address, saves the
     entry point address there, and returns to that address, leaving the
     resulting stack pristine and untouched for the original entry point. */
  asm volatile(
  	".intel_syntax noprefix\n"
	"mov ebx, %0\n"
	"mov eax, ebx\n"
	"sub eax, esp\n"
	"add eax,4\n"
	"mov edx, [ebx+4]\n"
	"add esp, eax\n"
	"mov ebx, [ebx]\n"
	"mov [esp], ebx\n"
	"xor ebp, ebp\n"
	"ret\n"
	".att_syntax\n"
	: 
	: "r" (&entry_address)
	:
  );
}

bool is_target(uintptr_t address, uint8_t *bytes){
  /* Suppress unused parameter warnings */
  (void)(address);
  (void)(bytes);
  return false;
}

/* Call our library so that the function is linked into our statically-linked binary */
int main(){
  uint8_t *orig_code = 0x0;
  size_t code_size = 0x0;
  uintptr_t address = 0x0;
  uintptr_t new_address = 0x0;
  size_t new_size = 0;

  register_handler();

  gen_code(orig_code, code_size, address,
    new_address, &new_size, 16, &is_target);
  return 0;
}
