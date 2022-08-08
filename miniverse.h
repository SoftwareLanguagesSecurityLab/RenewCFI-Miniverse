#ifdef __cplusplus
extern "C" {
#endif 

//#define RECORD_STATS
//#define ADD_SHADOW_STACK

#ifdef RECORD_STATS
#include <time.h>

struct longtimespec {
  time_t tv_sec;
  long long tv_nsec;
};

extern unsigned long long relocs_counter;
extern unsigned long long target_counter;

extern struct longtimespec rewrite_and_disasm_timer;
extern struct longtimespec just_rewrite_timer;
extern struct longtimespec reloc_patch_timer;
extern struct longtimespec realloc_timer;
extern struct longtimespec gen_ret_timer;
extern struct longtimespec gen_cond_timer;
extern struct longtimespec gen_uncond_timer;
extern struct longtimespec gen_none_timer;
#endif

#include <ssdis.h>
#include <pagealloc.h>

#ifdef ADD_SHADOW_STACK
extern uintptr_t shadow_stack_offset;
#endif

extern uintptr_t fixed_offset;

/* Defined in a different module (handlers.c), but declared here so we
   only need one header file when installing the library */
extern void register_handler(bool (*my_is_target)(uintptr_t address,
                                                  uint8_t *bytes,
                                                  uintptr_t code_base,
                                                  size_t code_size));

extern void translate_address(void** address);
extern bool in_code_region(uintptr_t address);

pa_entry_t gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address,
    uintptr_t *new_address, size_t *new_size,
    bool (*is_target)(uintptr_t address, uint8_t *bytes,
                      uintptr_t code_base, size_t code_size));

#ifdef __cplusplus
}
#endif
