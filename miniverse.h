#ifdef __cplusplus
extern "C" {
#endif 

#define RECORD_STATS

#ifdef RECORD_STATS
#include <time.h>

extern unsigned long long relocs_counter;
extern unsigned long long target_counter;

extern struct timespec rewrite_and_disasm_timer;
extern struct timespec just_rewrite_timer;
extern struct timespec reloc_patch_timer;
extern struct timespec realloc_timer;
extern struct timespec gen_ret_timer;
extern struct timespec gen_cond_timer;
extern struct timespec gen_uncond_timer;
extern struct timespec gen_none_timer;
#endif

#include <ssdis.h>
#include <pagealloc.h>

extern uintptr_t fixed_offset;

/* Defined in a different module (handlers.c), but declared here so we
   only need one header file when installing the library */
extern void register_handler(bool (*my_is_target)(uintptr_t address,
                                                  uint8_t *bytes,
                                                  uintptr_t code_base,
                                                  size_t code_size));

pa_entry_t gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address,
    uintptr_t *new_address, size_t *new_size,
    bool (*is_target)(uintptr_t address, uint8_t *bytes,
                      uintptr_t code_base, size_t code_size));

#ifdef __cplusplus
}
#endif
