#include "miniverse.h"
#include <string.h>

#define NOP 0x90
#define JMP_REL_SHORT 0xeb
#define JMP_REL_NEAR 0xe9

#define RELOC_INVALID 0
#define RELOC_OFF 1
#define RELOC_ABS 2

/*
  TODO: Specify 64- or 32-bit variables to depend on chosen architecture
*/
typedef struct mv_reloc_t{
  uint8_t type;
  uint64_t offset;
  uint64_t target;
} mv_reloc_t;

typedef struct mv_code_t{
  uint8_t *code;
  uint32_t *mapping;
  mv_reloc_t *relocs;
  size_t reloc_count;
  size_t reloc_size;
  uint64_t base;
  size_t code_size;
  uint64_t offset;
} mv_code_t;

void gen_insn(mv_code_t *code, size_t chunk_size, cs_insn *insn);
void inline gen_uncond(mv_code_t *code, cs_insn *insn);
void gen_reloc(mv_code_t *code, uint8_t type, uint64_t offset, uint64_t target);

uint8_t* gen_code(const uint8_t* bytes, size_t bytes_size,
    uint64_t address, uint8_t chunk_size){
  csh handle;
  cs_insn *insn;
  uint8_t result;
  mv_code_t code;
  mv_reloc_t rel;
  size_t r;
  code.offset = 0;
  code.base = address;
  code.mapping = malloc( sizeof(uint32_t) * bytes_size );
  code.code = malloc( bytes_size ); // Will re-alloc to accommodate increased size
  code.code_size = bytes_size;
  code.relocs = malloc( sizeof(mv_reloc_t) * bytes_size/2 ); //Will re-alloc if more relocs needed
  code.reloc_count = 0; //We have allocated space for relocs, but none are used yet.
  code.reloc_size = sizeof(mv_reloc_t) * bytes_size/2;
  
  ss_open(CS_ARCH_X86, CS_MODE_32, &handle);
  insn = cs_malloc(handle);

  while( result = ss_disasm_iter(handle, &bytes, &bytes_size, &address, insn) ){
    printf("0x%llx: %s\t%s\n", insn->address, insn->mnemonic, insn->op_str);
    if( result == SS_SUCCESS ){
      code.mapping[insn->address-code.base] = code.offset; // Set offset of instruction in mapping
      gen_insn(&code, chunk_size, insn);
    }else if( insn->id == X86_INS_JMP ){ // Special jmp instruction
      /* TODO: Patch special instruction */ 
      gen_insn(&code, chunk_size, insn);
    }else{ // Instruction is X86_INS_HLT; special hlt instruction
      /* TODO: Roll back to last unconditional control flow instruction */
      gen_insn(&code, chunk_size, insn);
    }
  }
 
  printf("Type\tOffset\t\tTarget\n");
  // Loop through relocations and patch target destinations
  for( r = 0; r < code.reloc_count; r++ ){
    rel = *(code.relocs+r);
    printf("%u\t0x%llx (%llu)\t0x%llx\n", rel.type, rel.offset, rel.offset, rel.target);
  }

  free(code.mapping);
  return code.code;
}

/* Generate a translated version of an instruction to place into generated code buffer. */
void gen_insn(mv_code_t* code, size_t chunk_size, cs_insn *insn){
  /* If we have selected a chunk size that is not zero, pad to chunk size
     whenever we encounter an instruction that does not evenly fit within a
     chunk.  Fill the padded area with NOP instructions.
  */
  if( chunk_size != 0 && (chunk_size - (code->offset % chunk_size) < insn->size) ){
    memset(code->code+code->offset, NOP, chunk_size - (code->offset % chunk_size));
    code->offset += chunk_size - (code->offset % chunk_size);
  }
  /* If we have a nonzero chunk size, then we need to ensure all call
     instructions are padded to right before the end of a chunk.
     TODO: Cover all variations of call instructions
  */
  if( chunk_size != 0 && (insn->id == X86_INS_CALL) && (code->offset % chunk_size < insn->size) ){
    memset(code->code+code->offset, NOP, (code->offset % chunk_size) - insn->size);
    code->offset += (code->offset % chunk_size) - insn->size;
  }
  /* Expand allocated memory for code to fit additional instructions */
  /* TODO: place this in a location that accounts for different code size
     for generated instructions */
  if( code->offset+insn->size+chunk_size >= code->code_size ){
    code->code_size *= 2;
    /* TODO: handle realloc failure, which will clobber code pointer */
    code->code = realloc(code->code, code->code_size);
  }
  if( insn->id == X86_INS_CALL || insn->id == X86_INS_JMP ){
    /* generate unconditional control flow */
    gen_uncond(code, insn);
  }else{
    memcpy(code->code+code->offset, insn->bytes, insn->size); // Copy insn's bytes to generated code 
    code->offset += insn->size; // Since instruction is not modified, increment by instruction size
  }
}

void inline gen_uncond(mv_code_t *code, cs_insn *insn){
  int32_t disp;
  memcpy(code->code+code->offset, insn->bytes, insn->size); // Copy insn's bytes into generated code 
  
  switch( *(insn->bytes) ){
    /* Jump with 4-byte offset (5-byte instruction) */
    case JMP_REL_NEAR:
      /* Retrieve jmp target offset, look up rewritten destination in mapping, and patch address */
      /* TODO: This approach will actually not work, because the mapping may not yet have an entry
         for code that must be jumped *forward* to, so this code will need to be moved to a second
         pass in which all statically identifiable targets are patched. */
      disp = *(int32_t*)(insn->bytes+1);
      //disp = code->mapping[insn->address+disp-code->base] - code->offset;
      //memcpy(code->code+code->offset+1, disp, 4);
      gen_reloc(code, RELOC_OFF, code->offset+1, insn->address+disp);
      code->offset += 5;
      break;
    /* Jump with 1-byte offset (2-byte instruction) */
    case JMP_REL_SHORT:
      /* Special case where we must extend the instruction to its longer form */
      disp = *(int8_t*)(insn->bytes+1);
      /* Patch initial byte of instruction from short jmp to near jmp */
      *(code->code+code->offset) = JMP_REL_NEAR;
      gen_reloc(code, RELOC_OFF, code->offset+1, insn->address+disp);
      /* TODO: special case where we must extend the instruction to its longer form */
      code->offset += 5; // Size of new, larger instruction
      break;
  }
}

void gen_reloc(mv_code_t *code, uint8_t type, uint64_t offset, uint64_t target){
  // TODO: re-allocate when running out of space for relocations
  mv_reloc_t *reloc = (code->relocs + code->reloc_count);
  reloc->type = type;
  reloc->offset = offset;
  reloc->target = target;
  code->reloc_count++;
}
