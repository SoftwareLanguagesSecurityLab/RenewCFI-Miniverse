#include <ssdis.h>

uint8_t* gen_code(const uint8_t* bytes, size_t bytes_size,
    uint64_t address){
  csh handle;
  cs_insn *insn;
  uint8_t result;
  uint64_t offset = 0;
  uint64_t base = address;
  uint32_t* mapping = malloc( sizeof(uint32_t) * bytes_size );
  uint8_t* code = malloc( bytes_size ); // Will re-alloc to accommodate increased size
  
  ss_open(CS_ARCH_X86, CS_MODE_64, &handle);
  insn = cs_malloc(handle);

  while( result = ss_disasm_iter(handle, &bytes, &bytes_size, &address) ){
    if( result == SS_SUCCESS ){
      mapping[insn->address-base] = offset;
      /* TODO: change offset depending on whether instruction changed */
      offset += insn->size;
    }
  }

  free(mapping);
  return code;
}
