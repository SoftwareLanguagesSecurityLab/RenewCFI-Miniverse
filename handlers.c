/* This file contains:
     -Shim functions intended to interpose on mmap and mprotect, prohibiting
      the W+X combination of permissions and instead passing a request
      for only W.  This allows the pages to be written to but not executed.
     -An interrupt handler for SIGSEGV, only for handling when a page marked
      W (by our previous functions?) is attempting to be executed.  This
      triggers the rewriter and redirects the original call from the writable
      page to the new rewritten executable page.  It also should set the
      original writable page to only be readable, I think....
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

typedef struct {
  uintptr_t	address;
  size_t	size;
  bool		rewritten;
  uintptr_t	new_address;
  size_t	new_size;
  pa_entry_t	backup; /* Backup copy of original bytes */
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
  region->backup.address = 0;
  region->backup.size = 0;
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
      buf++;
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
    "movl $5, %%eax\n"
    "movl %1, %%ebx\n"
    "movl %2, %%ecx\n"
    "movl $0, %%edx\n"
    "int $0x80\n"
    "movl %%eax, %0\n"
    : "=r" (f)
    : "g" (path), "g" (mode)
    : "ebx", "esi", "edi"
  );
  return f;
}

int my_read(int f, char* buf, unsigned int count){
  unsigned int bytes_read;
  asm volatile(
    "movl $3, %%eax\n"
    "movl %1, %%ebx\n"
    "movl %2, %%ecx\n"
    "movl %3, %%edx\n"
    "int $0x80\n"
    "movl %%eax, %0\n"
    : "=g" (bytes_read)
    : "g" (f), "g" (buf), "g" (count)
    : "ebx", "esi", "edi"
  );
  return bytes_read;
}

int my_close(int f){
  int result;
  asm volatile(
    "movl $6, %%eax\n"
    "movl %1, %%ebx\n"
    "int $0x80\n"
    "movl %%eax, %0\n"
    : "=g" (result)
    : "g" (f)
    : "ebx", "esi", "edi"
  );
  return result;
}

bool get_specific_segment(uintptr_t addr_in_segment,
                          uintptr_t *segment_start, uintptr_t *segment_end){
  char line[256];
  uintptr_t region_start,region_end;
  int f = my_open("/proc/self/maps", O_RDONLY);
  bool done = false;
  while( !done ){
    done = !file_get_line(line, 256, f);
    region_start = my_strtoul(line, NULL,16);
    region_end = my_strtoul(line+9,NULL,16);
    if( addr_in_segment >= region_start && addr_in_segment < region_end ){
      *segment_start = region_start;
      *segment_end = region_end;
      my_close(f);
      return true;
    }
  }
  my_close(f);
  return false;
}

bool is_proposed_range_valid(uintptr_t range_start, uintptr_t range_end){
  char line[256];
  uintptr_t region_start,region_end;
  if( range_end < range_start ){
#ifdef DEBUG
    printf("ALERT: I REALLY don't like 0x%x-0x%x\n", range_start, range_end);
#endif
    return false;
  }
  int f = my_open("/proc/self/maps", O_RDONLY);
  bool done = false;
  while( !done ){
    done = !file_get_line(line, 256, f);
    /* Extract region start and end addresses, and check if
       memory region falls within given range.  If so, then the
       range is not a valid candidate for new mmap */
    region_start = my_strtoul(line, NULL,16);
    region_end = my_strtoul(line+9,NULL,16);
    if( (region_start >= range_start && region_start <= range_end) ||
        (region_end >= range_start && region_end <= range_end) ){
      my_close(f);
#ifdef DEBUG
      printf("ALERT: I don't like 0x%x-0x%x\n", range_start, range_end);
#endif
      return false;
    }
  }
  my_close(f);
  return true;
}

bool find_segment_with_main(uintptr_t* segment_start, uintptr_t* segment_end){
  /* For now, simply find the first region in /proc/self/maps that is r-x.
     This is not going to be always correct. */
  char line[256];
  uintptr_t region_start,region_end;
  int f = my_open("/proc/self/maps", O_RDONLY);
  bool done = false;
  while( !done ){
    done = !file_get_line(line, 256, f);
    region_start = my_strtoul(line, NULL,16);
    region_end = my_strtoul(line+9,NULL,16);
    if( line[18] == 'r' && line[19] == '-' && line[20] == 'x' ){
      *segment_start = region_start;
      *segment_end = region_end;
      my_close(f);
      return true;
    }
  }
  my_close(f);
  return false;
}

void set_fixed_offset(uintptr_t segfault_addr, uintptr_t calling_addr){
  uintptr_t caller_table_start;
  uintptr_t caller_table_end;
  uint32_t i;

  if( !get_specific_segment(calling_addr,
                            &caller_table_start, &caller_table_end) ){
    printf("WARNING: Couldn't find segment for calling address 0x%x\n",
           calling_addr);
    printf("JIT code may have been entered via JMP instead of CALL.\n");
    if( !find_segment_with_main(&caller_table_start, &caller_table_end) ){
      printf("FATAL ERROR: Could not find r-x segment in memory maps!\n"); 
      _exit(EXIT_FAILURE);
    }
  }

  /* Try offsets spanning essentially the entire address range.
     If there is not a large empty region, then we simply can't allocate
     the memory we need.*/
  for( i = 0; i < 16; i++ ){
    if( is_proposed_range_valid(segfault_addr*4+fixed_offset-0x2000000*4,
                                segfault_addr*4+fixed_offset+0x2000000*4) &&
        is_proposed_range_valid(caller_table_start*4+fixed_offset,
                                caller_table_start*4+fixed_offset + 
                                (caller_table_end-caller_table_start)*4 ) ){
      return;
    }
    fixed_offset += 0x10000000;
  }
  printf("FATAL ERROR: Can't find acceptable offset for addrs 0x%x and 0x%x\n",
         segfault_addr, calling_addr);
  _exit(EXIT_FAILURE);
}

void mirror_specific_segment(uintptr_t addr_in_segment){
  char line[256];
  uintptr_t region_start,region_end,i;
  int f = my_open("/proc/self/maps", O_RDONLY);
  void* mapped_addr;
  bool done = false;
  while( !done ){
    done = !file_get_line(line, 256, f);
    region_start = my_strtoul(line, NULL,16);
    region_end = my_strtoul(line+9,NULL,16);
    if( addr_in_segment >= region_start && addr_in_segment < region_end ){
      /* Map a memory region at a fixed offset from the code with a duplicate
       * of the code contents */
      mapped_addr = __real_mmap((void*)(region_start*4+fixed_offset),
                                (region_end-region_start)*4,
                                PROT_WRITE|PROT_READ,
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
      if( mapped_addr == MAP_FAILED ){
        printf("FATAL ERROR: Could not map mirrored region at 0x%x-0x%x\n",
               (region_start*4+fixed_offset),
               (region_start*4+fixed_offset)+(region_end-region_start)*4);
        _exit(EXIT_FAILURE);
      }
      /* Manually copy each byte in the region to first of 4 bytes in duplicate;
         only the first byte should be checked anyway, and these values are not
         meant to be used in lookups */
      for( i = region_start; i < region_end; i++ ){
        *(uint8_t*)(i*4+fixed_offset) = *(uint8_t*)i;
      }
      my_close(f);
      return;
    }
  }
  my_close(f);
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
  /* I mirrored the code segments to handle attempts to jump to this code from
   * rewritten code.  However, this only mirrors segments present when the
   * program first registers the handler.  Any dynamically loaded modules
   * introduced into memory later won't be handled. */
  //mirror_code_segments();
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
#ifdef DEBUG
  printf("(mprotect YES) ADDR: 0x%x EXEC: %d WRITE: %d READ: %d\n", (uintptr_t)addr, PROT_EXEC&prot, PROT_WRITE&prot, PROT_READ&prot);
#endif
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
      }
      /* Indicate success; permissions for region are now RW regardless of
         original arguments to mprotect intending to make it non-writable */
      __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
      clock_gettime(CLOCK_MONOTONIC, &end_time);
      mprotect_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
      mprotect_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
      return 0;
    }
  }else if( (prot & PROT_WRITE) && get_code_region(&region,(uintptr_t)addr) ){
#ifdef DEBUG
    printf("Detected present region 0x%x (mprotect addr 0x%x) -> writable!\n", region->address, (uintptr_t)addr);
    printf("Copying from %x to %x, %x bytes!\n", (uintptr_t)((uintptr_t)region->backup.address+(addr-region->address)), (uintptr_t)addr, region->backup.size);
#endif
    /* Simply mprotect the entire region and set not writable,
       expanding if necessary */
    /* Check whether region extends beyond original, expand size if so */
    if( len + ((uintptr_t)addr - region->address) > region->size ){
      region->size = len + ((uintptr_t)addr - region->address);
    }
    __atomic_clear(&miniverse_lock, __ATOMIC_RELEASE);
#ifdef RECORD_STATS
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    mprotect_timer.tv_sec += end_time.tv_sec - start_time.tv_sec;
    mprotect_timer.tv_nsec += end_time.tv_nsec - start_time.tv_nsec;
#endif
    return __real_mprotect((void*)region->address, region->size, prot);
    /* If the code is being set to writable but not executable,
       AND if the address is in an existing region,
       restore original bytes to the region before program can write to it */
    //int result = __real_mprotect(addr,len,prot); /* Set writable first */
    /* Restore the bytes for full region or whichever sub-region has been
       set writable.  Choose the smaller of either the backup size or the
       length of the mprotected region, as we cannot write to addresses not
       set to writable, and it's possible for a sub-region to be set writable
       (in which we must copy using len so we don't copy beyond the writable
       region) or a new, larger region to be set writable (in which we must
       copy using backup size, as we only have as much to copy as is in the
       backup).
       After this sub-region is set back to executable it
       will be split into a separate region or expanded when we attempt to
       rewrite it. */
    //if( region->backup.size < len ){
      /* Check whether we have enough space before the end of the region */
    /*  if( region->size-((uintptr_t)addr-region->address) > region->backup.size){
        memcpy(addr,
             (void*)((uintptr_t)region->backup.address+(addr-region->address)),
             region->backup.size );
      }else{
        memcpy(addr,
             (void*)((uintptr_t)region->backup.address+(addr-region->address)),
             region->size - ((uintptr_t)addr-region->address) );
      }
    }else{*/
      /* Check whether we have enough space before the end of the region */
     /* if( region->size-((uintptr_t)addr-region->address) > len ){
        memcpy(addr,
             (void*)((uintptr_t)region->backup.address+(addr-region->address)),
             len );
      }else{
        memcpy(addr,
             (void*)((uintptr_t)region->backup.address+(addr-region->address)),
             region->size - ((uintptr_t)addr-region->address) );
      }
    }
    return result;*/
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
  /*pa_entry_t backup_mem;*/

#ifdef DEBUG
  printf("Calling real mprotect for orig: 0x%x, 0x%x\n", (uintptr_t)orig_code, code_size);
#endif
  /* Set original code to be readable and writable,
     regardless of what it was set to before,
     so we may disassemble it and write to it.
     TODO: Set as read-only afterwards to detect changes */
  __real_mprotect((void*)orig_code, code_size, PROT_READ|PROT_WRITE);

  old_mapping = region->mapping;

  page_alloc(&new_mem, code_size*22);

  /* Free old backup if one is present */
  /*if( region->backup.address != 0 ){
#ifdef DEBUG
    printf("Free old backup: 0x%x, len 0x%x\n", (uintptr_t)region->backup.address, region->backup.size);
#endif
    page_free(&region->backup);
  }*/
  /* Backup original bytes before rewriting and patching old code section */
  /*page_alloc(&backup_mem, code_size);
  memcpy(backup_mem.address, orig_code, code_size);
  region->backup = backup_mem;*/

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

//bool flippy = false;

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

/*  if( flippy ){
    flippy = false;
    return;
  }else{
    flippy = true;
  }*/

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

    set_fixed_offset(segfault_region->address, caller_address);

    /* Create huge memory buffer for lookup entries at a fixed offset
       TODO: Eventually change this from a hard-coded offset into memory
       somehow allocated in a mysterious region based on segment registers */
    /* Add extra buffer space before start of region for new regions that
       could be allocated at a lower address than the initial region */
    void* mapped_addr = __real_mmap(
        (void*)(segfault_region->address*4+fixed_offset-0x2000000*4),
        0x2000000*4+0x2000000*4,PROT_WRITE|PROT_READ,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if( mapped_addr == MAP_FAILED ){
      printf("FATAL ERROR: Could not map fixed offset region 0x%x-0x%x\n",
             (segfault_region->address*4+fixed_offset-0x2000000*4),
             (segfault_region->address*4+fixed_offset-0x2000000*4)+
                 0x2000000*4+0x2000000*4);
      _exit(EXIT_FAILURE);
    }

    mirror_specific_segment(caller_address);
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
