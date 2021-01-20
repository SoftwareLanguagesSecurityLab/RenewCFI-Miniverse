#ifdef __cplusplus
extern "C" {
#endif 

#define RECORD_STATS

#ifdef RECORD_STATS
extern unsigned long long relocs_counter;
extern unsigned long long target_counter;
#endif

#include <ssdis.h>
#include <pagealloc.h>

/* Defined in a different module (handlers.c), but declared here so we
   only need one header file when installing the library */
extern void register_handler(bool (*my_is_target)(uintptr_t address,
                                                  uint8_t *bytes,
                                                  uintptr_t code_base,
                                                  size_t code_size));

pa_entry_t gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address,
    uintptr_t *new_address, size_t *new_size, uint8_t chunk_size,
    bool (*is_target)(uintptr_t address, uint8_t *bytes,
                      uintptr_t code_base, size_t code_size));

#ifdef __cplusplus
}
#endif
