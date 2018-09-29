#include <ssdis.h>

#define NOP 0x90

uint8_t* gen_code(const uint8_t* bytes, size_t bytes_size,
    uint64_t address, uint8_t chunk_size){
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
      /* If we have selected a chunk size that is not zero, pad to chunk size
         whenever we encounter an instruction that does not evenly fit within a
         chunk.  Fill the padded area with NOP instructions.
      */
      if( chunk_size != 0 && (offset % chunk_size > insn->size) ){
        memset(code+offset, NOP, offset % chunk_size);
	offset += offset % chunk_size;
      }
      /* If we have a nonzero chunk size, then we need to ensure all call
         instructions are padded to right before the end of a chunk.
         TODO: Cover all variations of call instructions
      */
      if( chunk_size != 0 && (insn->id == X86_INS_CALL) && (offset % chunk_size > insn->size) ){
        memset(code+offset, NOP, (offset % chunk_size) - insn->size);
	offset += (offset % chunk_size) - insn->size;
      }
      mapping[insn->address-base] = offset; // Set offset of this instruction in mapping
      /* TODO: pass instruction to gen_insn function, which may alter instruction bytes/position */
      memcpy(code+offset, insn->bytes, insn->size); // Copy insn's bytes into generated code 
      /* TODO: change offset depending on whether instruction changed */
      offset += insn->size;
    }else if( insn->id == X86_INS_JMP ){ // Special jmp instruction
      /* TODO: Patch special instruction with 
    }else{ // Instruction is X86_INS_HLT; special hlt instruction
      /* TODO: Roll back to last direct control flow instruction */
    }
  }

  free(mapping);
  return code;
}

/* Generate a translated version of an instruction to place into generated code buffer. */
void gen_insn(uint8_t* code, uint64_t offset, cs_insn *insn){

}
