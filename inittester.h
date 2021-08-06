#include <elf.h>

void patch_relocs(Elf32_Rel* reloc, size_t count, void* address);
size_t load_library(int fd, void* address, void** lib_entry);
void* miniverse_init();
