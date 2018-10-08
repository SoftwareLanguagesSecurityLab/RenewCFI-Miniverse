#include <ssdis.h>

uint8_t* gen_code(const uint8_t* bytes, size_t bytes_size, uint64_t address, uint64_t new_address,
    size_t *new_size, uint8_t chunk_size, bool (*is_target)(uint64_t address, uint8_t *bytes));
