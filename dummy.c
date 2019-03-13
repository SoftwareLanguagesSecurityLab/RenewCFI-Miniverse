#include "miniverse.h"
#include "handlers.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int __real_mprotect(void *addr, size_t len, int prot);

/* TODO: I may want to name this function miniverse_init */
void miniverse_entry(uintptr_t entry_address, const char* entry_fname){
  int fd;
  //printf("Hello: 0x%x, %s\n", entry_address, entry_fname);
  /* Restore original entry point */
  fd = open(entry_fname, O_RDONLY);
  __real_mprotect((void*)(entry_address&0xfffff000), 0x2000, PROT_READ|PROT_WRITE);
  read(fd, (void*)entry_address, 0x1000);
  __real_mprotect((void*)(entry_address&0xfffff000), 0x2000, PROT_READ|PROT_EXEC); 
  asm volatile(
  	".intel_syntax noprefix\n"
	"mov edx, [%0+4]\n"
	".att_syntax\n"
	: 
	: "r" (&entry_fname)
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
