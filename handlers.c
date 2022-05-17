/* This file contains:
     -Shim functions intended to interpose on mmap and mprotect, prohibiting
      the W+X combination of permissions and instead passing a request
      for only W.  This allows the pages to be written to but not executed.
     -An interrupt handler for SIGSEGV, only for handling when a page marked
      W (by our previous functions?) is attempting to be executed.  This
      triggers the rewriter and redirects the original call from the writable
      page to the new rewritten executable page.
*/
//#define DEBUG
#include <sys/mman.h>
#include <signal.h>
#include "handlers.h"

#include "miniverse.h"
 
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ucontext.h>
#include <sys/ucontext.h> // For hardware-specific registers (TODO: Does not work as expected!)
#include <unistd.h>
#include <fcntl.h>

uintptr_t fixed_offset = 0x20000000;
uintptr_t fixed_offset_region_addr = 0x0;
#define FIXED_OFFSET_REGION_SIZE (0x2000000*4+0x2000000*4)

#ifdef RECORD_STATS
#include <time.h>

unsigned long long mmap_counter = 0;
unsigned long long mprotect_counter = 0;
unsigned long long handler_counter = 0;
unsigned long long rewrite_counter = 0;

struct timespec mmap_timer = {0,0};
struct timespec mprotect_timer = {0,0};
struct timespec handler_timer = {0,0};
struct timespec rewriter_timer = {0,0};
#endif

uintptr_t rewriter_region_start;
uintptr_t rewriter_region_end;

/* Access lock for wrappers and handler;
   Should only be accessed by atomic operations */
bool miniverse_lock;

/* Flag storing whether this is the first invocation of the segfault handler */
bool first_segfault = true;

void *__real_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);

int __real_mprotect(void *addr, size_t len, int prot);

void map_table_for_segment(uintptr_t addr_in_segment);

bool default_is_target(uintptr_t address, uint8_t *bytes,
                       uintptr_t code_base, size_t code_size){
  /* Suppress unused parameter warnings */
  (void)(address);
  (void)(bytes);
  (void)(code_base);
  (void)(code_size);
  return false;
}

bool (*is_target)(uintptr_t address, uint8_t *bytes,
                  uintptr_t code_base, size_t code_size) = &default_is_target;

/* Struct used for a cache of the entries in file /proc/self/maps */
typedef struct {
  uintptr_t region_start;
  uintptr_t region_end;
  uint8_t permissions;
  char name[7]; // Truncated start of region name
} maps_region_t;

size_t num_maps_entries = 0;
pa_entry_t maps_entries_mem = {NULL,0};

typedef struct {
  uintptr_t	address;
  size_t	size;
  bool		rewritten;
  uintptr_t	new_address;
  size_t	new_size;
  pa_entry_t	mapping;
} code_region_t;

void rewrite_region(code_region_t* region);

size_t num_code_regions = 0;
pa_entry_t code_regions_mem = {NULL,0};

/* Try to add a new region that the program is attempting to set as executable.
   If it is already present, we just set rewritten to be false again.
   Right now, we only add regions, as we would need to hook munmap to know if
   a memory region has been removed. */
void add_code_region(uintptr_t address, size_t size){
  size_t i;
  code_region_t* region;
  if( code_regions_mem.address == NULL ){
    /* Start by assuming we only need one page to hold data
       on all code regions, and allocate more pages later. */
    page_alloc(&code_regions_mem, 0x1000);
  }
  /* Allocate more pages for code regions table if we are running out of room */
  if( (num_code_regions + 1) * sizeof(code_region_t) > code_regions_mem.size ){
    page_realloc(&code_regions_mem, code_regions_mem.size + 0x1000 );
  }
  region = code_regions_mem.address;
  /* Iterate through all known regions.  If a matching region is already
     present, set its rewritten status to false and return.
     If specified size is bigger than the existing region, just expand it. */
  for( i = 0; i < num_code_regions; i++ ){
    if( region->address == address && region->size <= size ){
      region->size = size;
      if( region->rewritten ){
#ifdef DEBUG
        printf("Update code region 0x%x\n", (uintptr_t)region->address);
#endif
        region->rewritten = false;
      }
      return;
    }else if( address > region->address &&
              address < region->address+region->size){
      /* If a new region falls within an existing region, split it
         and omit the new region from that existing region.
         If instead the new region extends to the end of the old region
         or beyond the end, just shorten the old region. */
      /* Instead of the previous, try just expanding region if needed */
      if( size + (address - region->address) > region->size ){
        region->size = size + (address - region->address);
      }
      return;
      /*if( address+size < region->address+region->size ){
        // TODO: Handle splitting regions
        printf("FATAL ERROR: Splitting regions unimplemented!\n");
        abort();
      }else{
        region->size = address - region->address;
      }*/
    }
    region++;
  }
  /* If we made it here, the region was new, so save it. */
  region->address = address;
  region->size = size;
  region->rewritten = false;
  region->new_address = 0;
  region->new_size = 0;
  region->mapping.address = 0;
  region->mapping.size = 0;
  num_code_regions++;
}

/* Attempt to retrieve a region that the program attempted to set as executable.
   Returns false if the region is not present (should indicate an actual
   segfault), otherwise populates region argument.
   This lookup is performed only using the address, as we will only have the 
   faulting address for a segfault, not the size of a region. */
bool get_code_region(code_region_t** region, uintptr_t address){
  size_t i;
  *region = code_regions_mem.address;
  for( i = 0; i < num_code_regions; i++ ){
    if( (*region)->address <= address &&
        (*region)->address + (*region)->size > address ){
      return true;
    }
    (*region)++;
  }
  return false;
}

/* Determine if an address is in any region that the program attempted to set
   as executable.  Called by rewriter, so needs to be fast.  */
bool in_code_region(uintptr_t address){
  size_t i;
  code_region_t* region = code_regions_mem.address;
  for( i = 0; i < num_code_regions; i++ ){
    if( region->address <= address &&
        region->address + region->size > address ){
      return true;
    }
    region++;
  }
  return false;
}

int my_read(int, char*, unsigned int);

/* Get a single line from a file.  Lines should not exceed 255 characters.  */
bool file_get_line(char* buf, size_t size, int fd){
  for( size_t i = 0; i < size-1; i++){
    if( my_read(fd, buf, 1) == 0 ){
      *buf = '\0';
      return false;
    }
    if( *buf == '\n' ){
      buf++;
      *buf = '\0';
      return true;
    }
    buf++;
  }
  *buf = '\0';
  return true;
}

/* Implement a subset of strtoul's functionality to avoid
 * dynamic memory allocations */
/* Only implements hexadecimal, and base/str_end are ignored */
unsigned long my_strtoul(char* str, char **str_end, int base){
  (void)str_end;
  (void)base;
  unsigned long value = 0;
  char c = *str++;
  while( (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ){
    value <<= 4;
    if( c >= '0' && c <= '9' ){
      value += c - '0';
    }else if( c >= 'a' && c <= 'f' ){
      value += 10 + (c - 'a');
    }
    c = *str++;
  }
  return value;
}

int my_open(const char* path, int mode){
  int f;
  asm volatile(
    "int $0x80\n"
    : "=a" (f)
    : "0" (5), "b"(path), "c" (mode), "d" (0)
    : "memory"
  );
  return f;
}

int my_read(int f, char* buf, unsigned int count){
  unsigned int bytes_read;
  asm volatile(
    "int $0x80\n"
    : "=a" (bytes_read)
    : "0" (3), "b" (f), "c" (buf), "d" (count)
    : "memory"
  );
  return bytes_read;
}

int my_close(int f){
  int result;
  asm volatile(
    "int $0x80\n"
    : "=a" (result)
    : "0" (6), "b" (f)
    : "memory"
  );
  return result;
}

void cache_memory_maps(){
  char line[256];
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;

  num_maps_entries = 0;

  int f = my_open("/proc/self/maps", O_RDONLY);
  bool done = !file_get_line(line, 256, f);
  while( !done ){
    if( num_maps_entries == 1024 ){
      /* For now only support 1024 mapped regions so we don't have to
         dynamically expand the mapped memory for the cache.  This should
         be plenty for most programs. */
      printf("FATAL ERROR: Over 1024 /proc/self/maps entries unsupported!\n"); 
      _exit(EXIT_FAILURE);
    }
    maps[num_maps_entries].region_start = my_strtoul(line, NULL,16);
    maps[num_maps_entries].region_end = my_strtoul(line+9,NULL,16);
    if( line[18] == 'r' ){
      maps[num_maps_entries].permissions |= PROT_READ;
    }
    if( line[19] == 'w' ){
      maps[num_maps_entries].permissions |= PROT_WRITE;
    }
    if( line[20] == 'x' ){
      maps[num_maps_entries].permissions |= PROT_EXEC;
    }
    /* Copy only first 6 bytes */
    memcpy(maps[num_maps_entries].name,line+73,6);
    maps[num_maps_entries].name[6] = '\0';
    num_maps_entries++;
    /* In /proc/self/maps, the last line ends with a newline.
       If file_get_line returns false, that means it reached EOF, from
       after that last newline, so the buffer is empty if done is true. */
    done = !file_get_line(line, 256, f);
  }
  my_close(f);
}

bool get_specific_segment(uintptr_t addr_in_segment,
                          uintptr_t *segment_start, uintptr_t *segment_end){
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;
  for( size_t i = 0; i < num_maps_entries; i++ ){
    if( addr_in_segment >= maps[i].region_start && 
        addr_in_segment < maps[i].region_end ){
      *segment_start = maps[i].region_start;
      *segment_end = maps[i].region_end;
      return true;
    }
  }
  return false;
}

bool is_proposed_range_valid(uintptr_t range_start, uintptr_t range_end){
  if( range_end < range_start ){
#ifdef DEBUG
    printf("ALERT: I REALLY don't like 0x%x-0x%x\n", range_start, range_end);
#endif
    return false;
  }
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;
  for( size_t i = 0; i < num_maps_entries; i++ ){
    /* Check if memory region falls within given range.  If so,
       then the range is not a valid candidate for new mmap */
    if( (maps[i].region_start >= range_start && 
         maps[i].region_start <= range_end) ||
        (maps[i].region_end >= range_start &&
         maps[i].region_end <= range_end) ){
#ifdef DEBUG
      printf("ALERT: I don't like 0x%x-0x%x\n", range_start, range_end);
#endif
      return false;
    }
  }
  return true;
}

bool find_first_exec_segment(uintptr_t* segment_start, uintptr_t* segment_end){
  /* Simply find the first region in /proc/self/maps that is r-x.
     This is not going to be always correct.  In the future I may need to
     search for a "main" symbol.  I have changed this function's name from
     find_segment_with_main, and if I ever need that, I should create that
     function. */
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;
  for( size_t i = 0; i < num_maps_entries; i++ ){
    if( (maps[i].permissions & PROT_READ) && 
        !(maps[i].permissions & PROT_WRITE) &&
        (maps[i].permissions & PROT_EXEC) ){
      *segment_start = maps[i].region_start;
      *segment_end = maps[i].region_end;
      return true;
    }
  }
  return false;
}

bool find_segment_by_name(char* name,
                          uintptr_t* segment_start, uintptr_t* segment_end){
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;
  for( size_t i = 0; i < num_maps_entries; i++ ){
    /* Compare only the first 6 bytes of the name, as it's all that is
       currently stored in the cached entries from /proc/self/maps.
       If I ever need more characters than this, I will need to change
       how much is stored, which may require more memory to be allocated
       for the memory map entries */
    if( strncmp(maps[i].name,name,6) == 0 ){
      *segment_start = maps[i].region_start;
      *segment_end = maps[i].region_end;
      return true;
    }
  }
  return false;
}

void set_fixed_offset(uintptr_t segfault_addr, uintptr_t calling_addr){
  uintptr_t caller_seg_start = 0;
  uintptr_t caller_seg_end = 0;
  uintptr_t first_exec_seg_start;
  uintptr_t first_exec_seg_end;
  uintptr_t vdso_seg_start;
  uintptr_t vdso_seg_end;
  uint32_t i;
  bool calling_addr_valid = true;

  if( !get_specific_segment(calling_addr,
                            &caller_seg_start, &caller_seg_end) ){
    printf("WARNING: Couldn't find segment for calling address 0x%x\n",
           calling_addr);
    printf("JIT code may have been entered via JMP instead of CALL.\n");
    calling_addr_valid = false;
  }

  /* Calls to the vdso need to have a table as well */
  if( !find_segment_by_name("[vdso]\n", &vdso_seg_start, &vdso_seg_end) ){
    printf("FATAL ERROR: Could not find vdso in memory maps!\n"); 
    _exit(EXIT_FAILURE);
  }

  /* Get first executable segment.  This may be the same as caller_seg, if
     the jit code was entered via a jmp and the top address on the stack was
     invalid, or if the first executable segment is the same on that is calling
     the jit code.  However, if the jit code was entered by a jmp, AND the
     address at the top of the stack is valid, then caller_seg will be WRONG.
     However, this is very hard to determine from just the address.  Therefore,
     to handle all the cases I have encountered at once, I will try to ensure
     that there is space for BOTH code regions if the caller segment is
     different from the first executable segment. */
  if( !find_first_exec_segment(&first_exec_seg_start, &first_exec_seg_end) ){
    printf("FATAL ERROR: Could not find r-x segment in memory maps!\n"); 
    _exit(EXIT_FAILURE);
  }

  /* Try offsets spanning essentially the entire address range.
     If there is not a large empty region, then we simply can't allocate
     the memory we need.*/
  for( i = 0; i < 16; i++ ){
    if( is_proposed_range_valid(segfault_addr*4+fixed_offset-0x2000000*4,
                                segfault_addr*4+fixed_offset+0x2000000*4) &&
        (!calling_addr_valid || 
         is_proposed_range_valid(caller_seg_start*4+fixed_offset,
                                 caller_seg_start*4+fixed_offset + 
                                 (caller_seg_end-caller_seg_start)*4 ) ) &&
        is_proposed_range_valid(first_exec_seg_start*4+fixed_offset,
                                first_exec_seg_start*4+fixed_offset + 
                                (first_exec_seg_end-first_exec_seg_start)*4 ) &&
        is_proposed_range_valid(vdso_seg_start*4+fixed_offset,
                                vdso_seg_start*4+fixed_offset + 
                                (vdso_seg_end-vdso_seg_start)*4 ) ){
      /* Map tables for original memory regions immediately, now that we know
         the fixed offset.*/
      map_table_for_segment(first_exec_seg_start);
      if( calling_addr_valid && !(calling_addr >= first_exec_seg_start &&
            calling_addr < first_exec_seg_end) ){
        /* Only map table for caller address if it's in a different region than
           the first executable segment (to avoid trying to map it twice) */
        map_table_for_segment(calling_addr);
      }
      map_table_for_segment(vdso_seg_start);
      /* Create huge memory buffer for lookup entries at a fixed offset
         TODO: Eventually change this from a hard-coded offset into memory
         somehow allocated in a mysterious region based on segment registers */
      /* Add extra buffer space before start of region for new regions that
         could be allocated at a lower address than the initial region */
      fixed_offset_region_addr = segfault_addr*4+fixed_offset-0x2000000*4;
      void* mapped_addr = __real_mmap(
          (void*)(fixed_offset_region_addr),
          FIXED_OFFSET_REGION_SIZE,PROT_WRITE|PROT_READ,
          MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
      if( mapped_addr == MAP_FAILED ){
        printf("FATAL ERROR: Could not map fixed offset region 0x%x-0x%x\n",
               (fixed_offset_region_addr),
               (fixed_offset_region_addr)+FIXED_OFFSET_REGION_SIZE);
        _exit(EXIT_FAILURE);
      }
      return;
    }
    fixed_offset += 0x10000000;
  }
  printf("FATAL ERROR: Can't find acceptable offset for addrs 0x%x and 0x%x\n",
         segfault_addr, calling_addr);
  _exit(EXIT_FAILURE);
}

void map_table_for_segment(uintptr_t addr_in_segment){
  void* mapped_addr;
  maps_region_t* maps = (maps_region_t*)maps_entries_mem.address;
  for( size_t i = 0; i < num_maps_entries; i++ ){
    if( addr_in_segment >= maps[i].region_start &&
        addr_in_segment < maps[i].region_end ){
      /* Map a memory region at a fixed offset from the code with an empty
       * table indicating no lookups should be done */
      mapped_addr = __real_mmap((void*)(maps[i].region_start*4+fixed_offset),
                                (maps[i].region_end-maps[i].region_start)*4,
                                PROT_READ,
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
      if( mapped_addr == MAP_FAILED ){
        printf("FATAL ERROR: Could not map table region at 0x%x-0x%x\n",
               (maps[i].region_start*4+fixed_offset),
               (maps[i].region_start*4+fixed_offset)+
                 (maps[i].region_end-maps[i].region_start)*4);
        _exit(EXIT_FAILURE);
      }
      /* We do not perform a lookup if a byte is zero, the default value in
         the allocated region.  If this were to change, we would need to fill
         every 4th byte with a new value indicating no lookup is needed */
      return;
    }
  }
}

#ifdef RECORD_STATS
void print_stats(){
  printf("Call mmap: %llu\n", mmap_counter);
  printf("\t%lu s, %lu ns\n", mmap_timer.tv_sec, mmap_timer.tv_nsec);
  printf("Call mprotect: %llu\n", mprotect_counter);
  printf("\t%lu s, %lu ns (includes rewriter)\n", mprotect_timer.tv_sec, mprotect_timer.tv_nsec);
  printf("Exception handler: %llu\n", handler_counter);
  printf("\t%lu s, %lu ns (includes first rewrite)\n", handler_timer.tv_sec, handler_timer.tv_nsec);
  printf("Rewrites: %llu\n", rewrite_counter);
  printf("\t%lu s, %lu ns total\n", rewriter_timer.tv_sec, rewriter_timer.tv_nsec);
  printf("\t\t %lu s, %lu ns rewriting + disasm\n", rewrite_and_disasm_timer.tv_sec, rewrite_and_disasm_timer.tv_nsec );
#ifdef RECORD_DISASM_STATS
  printf("\t\t\t %lu s, %lu ns overall disasm\n", disasm_timer.tv_sec, disasm_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns new insts\n", new_inst_timer.tv_sec, new_inst_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns old inst, valid seq\n", valid_seq_timer.tv_sec, valid_seq_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns old inst, invalid seq\n", invalid_seq_timer.tv_sec, invalid_seq_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns end seq\n", end_seq_timer.tv_sec, end_seq_timer.tv_nsec );
#endif
  printf("\t\t %lu s, %lu ns rewriting\n", just_rewrite_timer.tv_sec, just_rewrite_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns allocating mem\n", realloc_timer.tv_sec, realloc_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns rets\n", gen_ret_timer.tv_sec, gen_ret_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns conds\n", gen_cond_timer.tv_sec, gen_cond_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns unconds\n", gen_uncond_timer.tv_sec, gen_uncond_timer.tv_nsec );
  printf("\t\t\t %lu s, %lu ns unmodified\n", gen_none_timer.tv_sec, gen_none_timer.tv_nsec );
  printf("\t\t %lu s, %lu ns patching relocs\n", reloc_patch_timer.tv_sec, reloc_patch_timer.tv_nsec );
  printf("Relocs: %llu\n", relocs_counter);
  printf("Targets: %llu\n", target_counter);
  printf("Number of code regions: %u\n", num_code_regions);
}
#endif

void register_handler(bool (*my_is_target)(uintptr_t address, uint8_t *bytes,
                            uintptr_t code_base, size_t code_size)){
  struct sigaction new_action, old_action;
  if( my_is_target != NULL ){
    is_target = my_is_target;
  }
  /* Use sa_sigaction instead of sa_handler */
  new_action.sa_handler = NULL;
  void* sig_handler = &sigsegv_handler;
  new_action.sa_sigaction = sig_handler;
  sigemptyset(&new_action.sa_mask); /* Don't block other signals */
  new_action.sa_flags = SA_SIGINFO; /* Specifies we want to use sa_sigaction */
  sigaction( SIGSEGV, &new_action, &old_action );
  page_alloc(&maps_entries_mem, 0x4000);
  cache_memory_maps();
  /* Record the starting and ending addresses of the region the rewriter is in.
     This will allow us to detect if a segfault occurs inside miniverse. */
  get_specific_segment((uintptr_t)&gen_code,
                       &rewriter_region_start, &rewriter_region_end);

#ifdef RECORD_STATS
  atexit(print_stats);
#endif
}

/* Create wrapper for printf that performs a no-op to try
   and test whether removing calls to printf solves our problem */
int __wrap_printf(const char * format, ...){
  (void)(format);
  return 0; // Perform no-op instead of printing something
}

/* TODO: consider never allowing setting the exec bit under any
   condition, as we don't want an application under our control to
   ever load any new executable code without it going through our
   rewriting process first. */
/* TODO: Check that the call to __real_mmap actually succeeds before assuming
   that the memory is actually going to be allocated; otherwise, someone could
   fool the rewriter into rewriting an arbitrary memory region. */
void *__wrap_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset){
#ifdef RECORD_STATS
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  mmap_counter++;
#endif
  /* Busy wait for access; do not allow multiple threads into wrappers
     or handler at the same time! */
  while( __atomic_test_and_set(&miniverse_lock, __ATOMIC_ACQUIRE) );
  if( (prot & PROT_EXEC) && (prot & PROT_WRITE) ){
#ifdef DEBUG
    printf("(mmap) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif
    prot &= ~PROT_EXEC; /* Unset the exec bit */
    /* Force length to be a multiple of the page size, which mmap implicitly
       does already, since it allocates at a page granularity.
       I assume large pages are not being used. */
    if( (length & 0xfffff000) < length ){
      length = (length & 0xfffff000) + 0x1000;
    }
    /* Get actual address, in case mmap is passed 0 for the address */
    void* real_addr = __real_mmap(addr,length,prot,flags,fd,offset);
    /* Verify mmap succeeded before adding code region */
    if( real_addr != MAP_FAILED ){
      add_code_region((uintptr_t)real_addr, length);
    } 
    __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    mmap_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
    mmap_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
    return real_addr;
  }
  __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  mmap_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
  mmap_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
  return __real_mmap(addr,length,prot,flags,fd,offset);
}

/* Prevent any page from dynamically being allowed to have exec permissions
   added, and if any other permissions are added we also want to remove exec
   privileges too.  TODO: Handle the same chunk of memory repeatedly having
   permissions changed, even after we may have rewritten it before */
int __wrap_mprotect(void *addr, size_t len, int prot){
#ifdef RECORD_STATS
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  mprotect_counter++;
#endif
  /* Busy wait for access; do not allow multiple threads into wrappers
     or handler at the same time! */
  while( __atomic_test_and_set(&miniverse_lock, __ATOMIC_ACQUIRE) );
  code_region_t* region;

#ifdef DEBUG
  printf("(mprotect) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif

  if( (prot & PROT_EXEC) ){
    /* Force len to be a multiple of the page size, which mprotect implicitly
       does already, since it changes permissions at a page granularity.
       I assume large pages are not being used. */
    if( (len & 0xfffff000) < len ){
      len = (len & 0xfffff000) + 0x1000;
    }
    add_code_region((uintptr_t)addr, len); 
    /* Always unset the exec bit if set */
    prot &= ~PROT_EXEC;
    if( (prot & PROT_WRITE) ){
      /* Also unset the write bit so we will detect attempts to change already
         rewritten code TODO: detect attempts to switch from exec to writable */
      prot &= ~PROT_WRITE;
    }else{
      /* If write is NOT set, then let's try rewriting this region immediately
         since we know the code is done writing to it for now.  Trying to
         proactively rewrite a region might cause some issues, but it also will
         partially address the issue of rewritten code attempting to indirect
         call into un-rewritten code.  This doesn't fix the issue for RWX code,
         but for generated code with good hygiene it should work. */
      get_code_region(&region, (uintptr_t)addr);
      
      /* Wait before pre-emptively rewriting until after first time
         we have encountered a segfault, so that we can safely allocate
         the fixed-offset tables first */
      if( !first_segfault ){
#ifdef DEBUG
        printf("Rewriting 0x%x (size 0x%x) early!\n", region->address, region->size);
#endif
        rewrite_region(region);
        /* Indicate success; permissions for region are set in rewrite_region
           and ignore the original arguments to mprotect */
        __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        mprotect_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
        mprotect_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
        return 0;
      }
    }
  }
  __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  mprotect_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
  mprotect_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
  return __real_mprotect(addr,len,prot);
}

void rewrite_region(code_region_t* region){

  /* TODO: Determine if it is EVER safe to free a mapping or rewritten code,
     as we may always have stale pointers floating around. */

  uint8_t *orig_code = (uint8_t *)(region->address);
  size_t code_size = region->size;
  //size_t i;
  //uint32_t offset;
  pa_entry_t new_mem;
  pa_entry_t old_mem;
  pa_entry_t old_mapping;

  /* If this region hasn't been rewritten before, check whether applying the
     fixed offset to it results in an address outside our allocated fixed
     offset memory region.  If so, try to allocate a special fixed offset
     region just for this jit region.  There is no guarantee that the target
     address will not already be occupied by some other memory region, or even
     partially overlap with our original region, which I'm not currently
     handling.
     If the region was ever rewritten, then new_address will not be zero.
     If the mmap fails, abort the program. */
  if( region->new_address == 0 &&
      (region->address*4+fixed_offset < fixed_offset_region_addr ||
      (region->address+region->size)*4+fixed_offset >=
          fixed_offset_region_addr+FIXED_OFFSET_REGION_SIZE ) ){
    void* mapped_addr = __real_mmap(
        (void*)(region->address*4+fixed_offset),
        region->size*4,PROT_WRITE|PROT_READ,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if( mapped_addr == MAP_FAILED ){
      printf("FATAL ERROR: JIT region required late allocation of fixed offset region 0x%x-0x%x, which could not be allocated\n",
             region->address*4+fixed_offset,
             region->address*4+fixed_offset + region->size*4);
      _exit(EXIT_FAILURE);
    }
  }

#ifdef DEBUG
  printf("Calling real mprotect for orig: 0x%x, 0x%x\n", (uintptr_t)orig_code, code_size);
#endif
  /* Set original code to be read-only,
     regardless of what it was set to before,
     so we may disassemble it and disallow future writes. */
  __real_mprotect((void*)orig_code, code_size, PROT_READ);

  old_mapping = region->mapping;

  page_alloc(&new_mem, code_size*22);

#ifdef RECORD_STATS
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  rewrite_counter++;
#endif
  region->mapping = gen_code(orig_code, code_size, region->address,
      (uintptr_t*)&new_mem.address, &new_mem.size, is_target);
#ifdef RECORD_STATS
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  rewriter_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
  rewriter_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif

  /* Patch old code, since after rewriting, it is out of date.
     TODO: There may be stale pointers into the old rewritten code, so this
     probably cannot actually be freed safely.  However, let's try doing
     this anyway, because those stale pointers into the old rewritten code
     might also fail, since they would be pointing to stale code.  It would
     be better to have an obvious, immediate segfault than have wrong code
     run.  If I find code that fails due to trying to jump to unmapped code
     that was previously rewritten, then I can fix it then. */
  /* Now that we don't generate pointers to our rewritten code, try to just
     free this memory */
  if( region->new_address != 0 ){
/*#ifdef DEBUG
    printf("Patch old rewritten code: 0x%x (len 0x%x)\n", region->new_address, region->new_size);
#endif
    __real_mprotect((void*)region->new_address, region->new_size, PROT_READ|PROT_WRITE);
    for( i = 0; i < old_mapping.size/4; i++ ){
      offset = *((uint32_t*)old_mapping.address+i);
#ifdef DEBUG
      if( offset >= region->new_size ){
        printf("WARNING: Too large offset 0x%x\n", offset);
      }
#endif
      if( offset < region->new_size && offset % 16 == 0 && i < region->mapping.size/4){ */
        /* Patch in address at target in old rewritten code with the true
           destination in the new rewritten code, which we REALLY HOPE is also
           aligned.  OR with 0x3 to indicate a valid entry, will be masked */
	/* TODO MASK: Add back OR with 0x3 */
       /* *((uint32_t*)region->new_address+offset/4) = \
            (*((uint32_t*)region->mapping.address+i)+(uint32_t)new_mem.address);
       */     //(*((uint32_t*)region->mapping.address+i)+(uint32_t)new_mem.address)|0x3;
  /*    }
    }*/
    /* Free old mapping, which must have been present if we got here */
    page_free(&old_mapping);
    old_mem.address = (void*)region->new_address;
    old_mem.size = region->new_size;
    page_free(&old_mem); // Try freeing old code
  }

  region->new_address = (uintptr_t)new_mem.address;
  region->new_size = (uintptr_t)new_mem.size;

  size_t pages = (new_mem.size/0x1000);

#ifdef DEBUG
  printf("Calling real mprotect for exec: 0x%x, 0x%x\n", region->new_address, 0x1000*pages);
#endif

  /* Call the real, un-wrapped mprotect to actually set these pages
     as executable */
  __real_mprotect((void*)region->new_address, 0x1000*pages, PROT_EXEC);

#ifdef DEBUG
  printf("Region 0x%x is rewritten\n", region->address);
#endif
  region->rewritten = true;
}

void translate_address(void** address){
  code_region_t* region;

  if( !get_code_region(&region, (uintptr_t)*address) ){
    /* Don't translate address if it's not recognized */
    return;
  }
  if( !region->rewritten ){
    printf("Region not yet rewritten in translate_address!\n");
    return;
  }

  uintptr_t old_address = (uintptr_t)*address;
  *address = (void*)((uintptr_t)region->new_address +
      ((uint32_t*)region->mapping.address)[old_address-region->address]);

}

/* TODO: refer to REG_EIP using a system header rather than this define */
#define REG_EIP 14
/* TODO: refer to REG_ESP using a system header rather than this define */
#define REG_ESP 7
/* Catch all segfaults here and detect attempts to execute generated code
   so that we can rewrite it or redirect it to existing rewritten code. */
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext){
  (void)(sig);
  (void)(info);
  ucontext_t *con = (ucontext_t*)ucontext;
  /* Retrieve the address of the instruction pointer.  If the address is in
     a region that needs rewriting, rewrite it. */
  uintptr_t target = con->uc_mcontext.gregs[REG_EIP];
  code_region_t* segfault_region;

#ifdef RECORD_STATS
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  handler_counter++;
#endif

  /* Check that this segfault did not occur inside the same memory region as
     miniverse.  If it did, exit with a fatal error. */
  if( target >= rewriter_region_start && target < rewriter_region_end ){
    printf("FATAL ERROR: non-jit segfault at 0x%x (offset 0x%x)\n", target,
           target - rewriter_region_start );
    /* Exit as soon as possible, don't bother with abort because it raises
       a catchable SIGABRT signal */
    _exit(EXIT_FAILURE);
  }
  
  while( __atomic_test_and_set(&miniverse_lock, __ATOMIC_ACQUIRE) );

  /* Check whether instruction pointer is in a known code region (a region we
     know we need to rewrite because we encountered it in an mmap or mprotect
     call).  If not, then the segfault must have been triggered by some actual
     invalid memory access, so abort. */
  if( !get_code_region(&segfault_region, target) ){
#ifdef DEBUG
    printf("WARNING: 0x%x is untracked, attempting lookup.\n", target);
#endif
    /* TODO MASK: The test checking whether this is a target previously failed
       or else it would have already looked up a target that should have worked,
       so it's really confusing as to why I would perform a lookup here.
       We perform this lookup when NO code region matches, so we're doing a
       lookup on a target that we have no idea of the origin of!  In what case
       does looking up an unidentified target make sense?
       Unless I find evidence otherwise, I'm commenting out this fallback
       because I don't think it accomplishes anything. */
    //if( (*((uint32_t*)target) & 0x3) ){
    //if( *((uint32_t*)target) & 0x3 ){
      /* Set instruction pointer to masked target lookup */;
    //  con->uc_mcontext.gregs[REG_EIP] =
          /* TODO MASK: Restore proper mask */
    //      (uintptr_t)(*((uint32_t*)target) & 0xffffffff);
          //(uintptr_t)(*((uint32_t*)target) & 0xfffffff0);
    //  return;
    //}else{
      printf("FATAL ERROR: 0x%x never encountered in mmap/mprotect!\n", target);
      /* Exit as soon as possible, don't bother with abort because it raises
         a catchable SIGABRT signal */
      _exit(EXIT_FAILURE);
    //}
  }

  /* If this is the first time this handler has been invoked */
  if( first_segfault ){
    first_segfault = false;
    /* Pull the top address off the stack, which should be a return address
     * if the dynamically generated code was called, rather than jumped to.
     * Assume for now that the code was indeed called. */
    uintptr_t caller_address = *(uintptr_t*)con->uc_mcontext.gregs[REG_ESP];

    /* Re-cache memory maps in case new regions have been mapped since the
       segfault handler was registered */
    cache_memory_maps();
    set_fixed_offset(segfault_region->address, caller_address);
  }
  //printf( "Stats for region @ 0x%x: 0x%x, %d, %d, 0x%x, 0x%x\n", (uintptr_t)region, region->address, region->size, region->rewritten, region->new_address, (uintptr_t)region->mapping.address);
  /* If region has not been rewritten yet, rewrite it and all other regions
     that have not yet been rewritten.  This is important in case there are
     cross-region jumps! */
  if( !segfault_region->rewritten ){
#ifdef RECORD_STATS
    printf("Rewriting in handler!\n");
#endif
    code_region_t* region = code_regions_mem.address;
    for( size_t i = 0; i < num_code_regions; i++ ){
      if( !region->rewritten ){
        rewrite_region(region);
      }
      region++;
    }
  }

  /* Set instruction pointer to corresponding target in rewritten code */;
  con->uc_mcontext.gregs[REG_EIP] =
      (uintptr_t)(segfault_region->new_address + 
      ((uint32_t*)segfault_region->mapping.address)[target-segfault_region->address]);

  __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  handler_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
  handler_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
}
