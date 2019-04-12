#include <ssdis.h>
#include <pagealloc.h>

/* Defined in a different module (handlers.c), but declared here so we
   only need one header file when installing the library */
extern void register_handler(bool (*my_is_target)(uintptr_t address, uint8_t *bytes));

pa_entry_t gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address,
    uintptr_t *new_address, size_t *new_size, uint8_t chunk_size,
    bool (*is_target)(uintptr_t address, uint8_t *bytes));
