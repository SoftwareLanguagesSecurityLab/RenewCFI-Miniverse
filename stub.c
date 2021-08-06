#include "miniverse.h"

bool my_is_target(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size){
  return false;
}

int main(int argc, char** argv){
  register_handler(&my_is_target);
  return 0;
}
