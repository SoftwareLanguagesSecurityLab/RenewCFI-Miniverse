#include <elf.h>

void patch_relocs(Elf32_Rel* reloc, size_t count, void* address);
size_t load_binary(int fd, void* address);
void* miniverse_init();
