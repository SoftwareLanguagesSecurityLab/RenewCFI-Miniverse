#include <ssdis.h>
#include <pagealloc.h>

uint32_t* gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address, uintptr_t new_address,
    size_t *new_size, uint8_t chunk_size, bool (*is_target)(uintptr_t address, uint8_t *bytes));
