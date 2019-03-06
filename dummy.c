#include "miniverse.h"
#include "handlers.h"

/* TODO: I may want to name this function miniverse_init */
void miniverse_entry(uintptr_t entry_address, uintptr_t orig_entry){
  printf("Hello: %ld, %ld\n", entry_address, orig_entry);
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
