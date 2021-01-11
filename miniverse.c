#include "miniverse.h"
#include <string.h>
#include <sys/mman.h>
#include <assert.h>

#define DO_RET_LOOKUPS 1
#define PUSH_OLD_ADDRESSES 1

#define NOP 0x90
#define RET_NEAR 0xc3
#define RET_NEAR_IMM 0xc2
#define CALL_REL_NEAR 0xe8
#define JMP_REL_SHORT 0xeb
#define JMP_REL_NEAR 0xe9
#define CALL_JMP_INDIRECT 0xff
#define JCC_REL_NEAR 0x0f

/* Use this to identify targets */
/* TODO MASK: Restore original masking code */
#define TARGET_LABEL 0x9b

#define FIXED_OFFSET 0x40000000

#define RELOC_INVALID 0
#define RELOC_OFF 1
#define RELOC_IND 2
#define RELOC_ABS 3

/* TODO: Perhaps we should do two independent passes
   without storing relocation data.  The more data stored
   in data structures, the larger the potential attack surface.
*/

/*
  TODO: Specify 64- or 32-bit variables to depend on chosen architecture
*/
typedef struct mv_reloc_t{
  uint8_t type;
  uint32_t offset;
  uintptr_t target;
} mv_reloc_t;

typedef struct mv_code_t{
  uint8_t *code;
  pa_entry_t code_mem;
  uint32_t *mapping;
  pa_entry_t reloc_mem;
  mv_reloc_t *relocs;
  size_t reloc_count;
  size_t last_safe_reloc; // Last reloc before the most recent unconditional jump or ret
  uintptr_t base;
  size_t orig_size;
  size_t code_size;
  uint8_t chunk_size;
  uint32_t offset;
  uint32_t last_safe_offset; // Last offset before the most recent unconditional jump or ret
  uintptr_t mask;
  bool (*is_target)(uintptr_t address, uint8_t *bytes,
                    uintptr_t code_base, size_t code_size);
#ifdef DO_RET_LOOKUPS
  bool was_prev_inst_call;
#endif
} mv_code_t;

/* TODO MASK: Restore original masking code */
uint8_t ret_template[] = "\x87\x04\x24\xf6\x00\x03\x0f\x44\x00";
//uint8_t ret_template[] = "\x87\x04\x24\xf6\x00\x03\x0f\x45\x00";
#ifdef PUSH_OLD_ADDRESSES
uint8_t pop_jmp_template[] = "\x87\x04\x24\xf6\x80\x00\x00\x00\x40\x03";
/* Only here because adding a fixed offset forces me to split this */
uint8_t pop_jmp_template2[] = "\x0f\x44\x80\x00\x00\x00\x40";
uint8_t pop_jmp_imm_template[] = "\x87\x04\x24\xf6\x80\x00\x00\x00\x40\x03";
uint8_t pop_jmp_imm_template2[] = "\x0f\x44\x80\x00\x00\x00\x40\x87\x04\x24\x81\xc4\xff\xff\x00\x00";
#endif
/* TODO MASK: Restore original masking code */
uint8_t ret_template_mask[] = "\x83\xe0\xff\x87\x04\x24";
//uint8_t ret_template_mask[] = "\x83\xe0\xf0\x87\x04\x24";
#ifdef PUSH_OLD_ADDRESSES
uint8_t pop_jmp_template_mask[] = "\x87\x04\x24\x83\xc4\x04\x80\x64\x24\xfc\xff\xff\x64\x24\xfc";
uint8_t pop_jmp_imm_template_mask[] = "\x80\xa4\x24\xff\xff\xff\xff\xff\xff\xa4\x24\xff\xff\xff\xff";
#endif
uint8_t indirect_template_before[] = "\x50\x8b";
/* TODO MASK: Restore original masking code */
uint8_t indirect_template_after[] = "\xf6\x80\x00\x00\x00\x40\x03\x0f\x44\x80\x00\x00\x00\x40";
//uint8_t indirect_template_after[] = "\xf6\x00\x03\x0f\x45\x00";
#ifdef PUSH_OLD_ADDRESSES
uint8_t indirect_template_mask_push_jmp[] = "\x24\xff\x50\x58\x58\x68\xff\xff\xff\xff\xff\x64\x24\xfc";
#endif
/* TODO MASK: Restore original masking code */
/* TODO: Why is the AND in long form if there's a shorter form available? */
uint8_t indirect_template_mask_call[] = "\x25\xff\xff\xff\xff\x50\x58\x58\xff\x54\x24\xf8";
//uint8_t indirect_template_mask_call[] = "\x25\xf0\xff\xff\xff\x50\x58\x58\xff\x54\x24\xf8";
/* TODO MASK: Restore original masking code */
/* TODO: Why is the AND in long form if there's a shorter form available? */
uint8_t indirect_template_mask_jmp[] = "\x25\xff\xff\xff\xff\x50\x58\x58\xff\x64\x24\xf8";
//uint8_t indirect_template_mask_jmp[] = "\x25\xf0\xff\xff\xff\x50\x58\x58\xff\x64\x24\xf8";

bool is_pic(mv_code_t *code, uintptr_t address);

void gen_insn(mv_code_t *code, ss_insn *insn);
static inline void gen_ret(mv_code_t *code, ss_insn *insn);
static inline void gen_cond(mv_code_t *code, ss_insn *insn);
static inline void gen_uncond(mv_code_t *code, ss_insn *insn);
void gen_indirect(mv_code_t *code, ss_insn *insn);
void gen_padding(mv_code_t *code, ss_insn *insn, uint16_t new_size);
void check_target(mv_code_t *code, ss_insn *insn);
void gen_reloc(mv_code_t *code, uint8_t type, uint32_t offset, uintptr_t target);
size_t sort_relocs(mv_code_t *code);

pa_entry_t gen_code(const uint8_t* bytes, size_t bytes_size, uintptr_t address,
    uintptr_t *new_address, size_t *new_size, uint8_t chunk_size,
    bool (*is_target)(uintptr_t address, uint8_t *bytes,
                      uintptr_t code_base, size_t code_size)){
  ss_handle handle;
  ss_insn insn;
  uint8_t result;
  mv_code_t code;
  mv_reloc_t rel;
  pa_entry_t mapping_mem;
  size_t r;
  size_t trimmed_bytes = 0; // This variable is optional, as it's just used to collect a metric.
  code.offset = 0;
  code.last_safe_offset = 0;
  /* TODO MASK: Restore original masking code */
  //code.mask = -1;
  code.mask = -1 ^ (chunk_size-1); // TODO: Mask off top bits in future
  code.base = address;
  page_alloc( &mapping_mem, sizeof(uint32_t) * bytes_size );
  code.mapping = mapping_mem.address;
  code.code = (uint8_t*) *new_address;// Will allocate more pages if needed
  code.code_mem.address = (void*)(*new_address);
  code.code_mem.size = *new_size;
  code.code_size = *new_size;// Start with however much the caller allocated
  code.chunk_size = chunk_size;
  code.orig_size = bytes_size; //Capstone decrements the original size variable, so we must save it
  page_alloc( &code.reloc_mem, sizeof(mv_reloc_t) * bytes_size );
  code.relocs = code.reloc_mem.address; //Will re-alloc if more relocs needed
  code.reloc_count = 0; //We have allocated space for relocs, but none are used yet.
  code.last_safe_reloc = 0;
  code.is_target = is_target;
#ifdef DO_RET_LOOKUPS
  code.was_prev_inst_call = false;
#endif
  
  ss_open(SS_MODE_32, false, &handle, bytes, bytes_size, (uint64_t)address);

  while( (result = ss_disassemble(&handle, &insn)) ){
    if( result == SS_SUCCESS ){
      //printf("0x%llx: %s\t(%x)\n", insn.address, insn.insn_str, code.offset);
      /* Put off writing to mapping until padding has been added to fit
         instruction, so that mapping is equal to relocations */
      //code.mapping[insn.address-code.base] = code.offset; // Set offset of instruction in mapping
      gen_insn(&code, &insn);
    }else if( insn.id == SS_INS_JMP ){ // Special jmp instruction
      /* TODO: Patch special instruction */ 
      //printf("0x%llx: %s\t(SPECIAL)\n", insn.address, insn.insn_str);
      gen_insn(&code, &insn);
    }else{ // Instruction is SS_INS_HLT; special hlt instruction
      /* Roll back to last unconditional control flow instruction, because all code following it
         ends up potentially flowing into an invalid instruction */
      /* Since we stop at unconditional jumps, and roll back to them whenever we encounter this
         special hlt, we ensure that the end of the generated code (or any generated code that
         leads up to the end of the original code bytes) ends at the last one of the unconditional
         jumps found.  However,
         TODO: We should not allow spare bytes to remain outside the safely generated code, so any
         extra space still allocated that we are not using (such as the rest of a page) should be
         filled with hlt instructions */
#ifdef DEBUG
      printf("0x%llx: %s\t(SPECIAL)\n", insn.address, insn.insn_str);
      printf("%u bytes trimmed\n", code.offset - code.last_safe_offset);
#endif
      trimmed_bytes += (code.offset - code.last_safe_offset);
      code.offset = code.last_safe_offset;
      code.reloc_count = code.last_safe_reloc;
#ifdef DO_RET_LOOKUPS
      code.was_prev_inst_call = false;
#endif
      //gen_insn(&code, insn);
    }
  }

#ifdef DEBUG
printf("Setting text section to writable: %x, %x bytes\n", address, code.orig_size);
#endif
  /* Make original text section writable before patching relocs, since we will need to modify it */
  /* Assume original text section has been set to writable by caller */
  //mprotect((void*)address, code.orig_size, PROT_READ|PROT_WRITE);
 
  sort_relocs(&code);
  //printf("Type\tOffset\t\tTarget\t\tNew Target\tDisplacement\n");
  // Loop through relocations and patch target destinations
  for( r = 0; r < code.reloc_count; r++ ){
    rel = code.relocs[r];
    if( rel.type == RELOC_OFF ){
      /* If target is in mapping, update entry.  Otherwise, we probably want to
         somehow check if this target is a valid target in a separate module.
         We only need to check whether (rel.target - code.base) is less than
         the original size and not check whether it is >= 0 because both
         numbers are unsigned and therefore would instead just wrap around to
         a very large positive number if the target address is before the base
         address.
         TODO: Handle targets outside mapping! */
      if( rel.target - code.base < code.orig_size ){
        //printf("%u\t0x%x (%u)\t0x%x\t0x%x\t\t%d\n", rel.type, rel.offset, rel.offset, rel.target, code.mapping[rel.target-code.base], code.mapping[rel.target-code.base] - (rel.offset+4));
        *(uint32_t*)(code.code + rel.offset) = code.mapping[rel.target-code.base] - (rel.offset+4);
      }else{
        //printf("%u\t0x%x (%u)\t0x%x\tN/A\t\tN/A\n", rel.type, rel.offset, rel.offset, rel.target);
        *(uint32_t*)(code.code + rel.offset) = rel.target - ((uintptr_t)code.code + rel.offset + 4);
      }
    }else if( rel.type == RELOC_IND ){
      /* Unlike for RELOC_OFF type, we write directly to the target, placing the new base address
         plus the offset directly at that address in the original text section */  
      //printf("%u\t0x%x (%u)\t0x%x\tN/A\t\tN/A\n", rel.type, rel.offset, rel.offset, rel.target);
      if( code.mapping[rel.target-code.base] != rel.offset ){
        printf("WARNING: Mapping (0x%x) and reloc (0x%x) do not agree!\n",
               code.mapping[rel.target-code.base],
               rel.offset);
      }
      if( r != code.reloc_count-1 && code.relocs[r+1].target - rel.target < 4 ){
#ifdef DEBUG
        printf("WARNING: Target %x overlaps with another target\n", rel.target);
#endif
        /* Patch first byte to force indicator that is is NOT a target
           by replacing first byte with a nop */
        /* TODO: Patching with a nop does not work because the target is always
           masked off regardless of whether it is a target or not.  This means
           that the original target will be lost and the masked address will
           become an invalid target, resulting in a crash.  This approach does
           not work in its current implementation. */
        /* TODO: Patching with an alternate label, 0x9b (fwait), can work, but
           only if masking of targets is not done, meaning that SFI is not
           being enforced at all.  This will result in easier testing for a
           proof-of-concept, but not an effective solution for an actual
           defense. */
        *(uint8_t*)(rel.target+FIXED_OFFSET) = TARGET_LABEL;
      }else if( rel.target <= (uintptr_t)code.base+code.orig_size-4 ){
        *(uint32_t*)(rel.target+FIXED_OFFSET) = (uintptr_t)code.code + rel.offset;
      }else{
        printf("WARNING: Target too close to code boundary\n");
      }
    }
  }

  /* Remove write permission from original text section after modifying it */
  //mprotect((void*)address, code.orig_size, PROT_READ);

#ifdef DEBUG
  printf("Original code size: %d\n", code.orig_size);
  printf("Generated code size: %d(0x%x)\n", code.offset, code.offset);
  printf("Total bytes trimmed: %d\n", trimmed_bytes);
  printf("New code address: 0x%x\n", (uintptr_t)code.code);
#endif
  //free(code.mapping);
  page_free(&code.reloc_mem);
  *new_size = code.code_size;
  *new_address = (uintptr_t)code.code;
  return mapping_mem;
}

/* Generate a translated version of an instruction to place into generated code buffer. */
void gen_insn(mv_code_t* code, ss_insn *insn){
  /* Expand allocated memory for code to fit additional instructions and padding */
  if( code->offset + (3*code->chunk_size) >= code->code_size ){
    /* Allocate one new page and increase code size to reflect the new size */
#ifdef DEBUG
    printf("Increasing new code size: %d >= %d (0x%x)\n",
        code->offset + (3*code->chunk_size),
        code->code_size, (uintptr_t)code->code_mem.address);
#endif
    if( page_realloc(&code->code_mem, code->code_size+0x1000) ){
      code->code = code->code_mem.address;
      code->code_size = code->code_mem.size;
#ifdef DEBUG
      printf("Newly allocated: 0x%x\n", (uintptr_t)code->code_mem.address);
#endif
    }else{
      puts("ERROR: Failed to allocate memory for new code");
    }
  }
  /* Rewrite instruction, using the instruction id to determine what kind
     of instruction it is */
  switch( insn->id ){
    case SS_INS_RET:
      gen_ret(code, insn);
      break;
    case SS_INS_JMP:
    case SS_INS_CALL:
      /* generate unconditional control flow */
      gen_uncond(code, insn);
      break;   
    case SS_INS_JAE:
    case SS_INS_JA:
    case SS_INS_JBE:
    case SS_INS_JB:
    case SS_INS_JCXZ:
    case SS_INS_JECXZ:
    case SS_INS_JE:
    case SS_INS_JGE:
    case SS_INS_JG:
    case SS_INS_JLE:
    case SS_INS_JL:
    case SS_INS_JNE:
    case SS_INS_JNO:
    case SS_INS_JNP:
    case SS_INS_JNS:
    case SS_INS_JO:
    case SS_INS_JP:
    case SS_INS_JRCXZ:
    case SS_INS_JS:
      /* generate conditional control flow */
      gen_cond(code, insn);
      break;
    // If there is no match, just pass instruction through unmodified
    default:
      gen_padding(code, insn, insn->size); 
      check_target(code, insn);
      /* Special case code for call to PIC, specifically the get_pc_thunk pattern.
         If PIC, we need to change instruction to read the argument passed on the stack
         instead of the return address */
      if( is_pic(code, insn->address) ){
        *(uint32_t*)(code->code+code->offset) = 0x04244c8b; // Encoding of mov ecx,[esp+4]
        code->offset += 4; // Size of new instruction 
      }else{
        memcpy(code->code+code->offset, insn->bytes, insn->size); // Copy insn's bytes to gen'd code 
        code->offset += insn->size; // Since insn is not modified, increment by instruction size
      }
  }
#ifdef DO_RET_LOOKUPS
  if( insn->id == SS_INS_CALL ){
    code->was_prev_inst_call = true;
  }else{
    code->was_prev_inst_call = false;
  }
#endif
}

#ifdef DO_RET_LOOKUPS
inline void gen_ret(mv_code_t *code, ss_insn *insn){
  //printf("RET: %llx %s\n", insn->address, insn->insn_str);
  /* Rewrite ret instructions to perform lookups just like indirect
     jmp and call instructions, in case the return address is an old
     address that was not placed on the stack by one of our rewritten
     call instructions */
  /* TODO: Handle far returns */
  /*
    xchg eax,[esp]
    test byte ptr [eax], 3
    cmovnz eax,[eax]
    ---                       (chunk boundary)
    and eax, 0xFFFFFFF0
    xchg eax,[esp]
    ret <imm?>
  */
  /* If PUSH_OLD_ADDRESSES is set, I use these instructions instead,
     so that this becomes essentially a pop-jump pair.
    xchg eax,[esp]
    test byte ptr [eax], 0x3
      (OR test byte ptr [eax+0x40000000], 0x3 for fixed lookup offset)
    cmov(n)z eax,[eax]
      (OR cmov(n)z eax,[eax+0x40000000] for fixed lookup offset, and
       in its own chunk, because that's the only way I could fit it)
    xchg [esp],eax        <- pushed to next chunk for fixed lookup offset
    add esp,4             <- pushed to next chunk for fixed lookup offset
    ---                      (chunk boundary)
    and byte ptr [esp-4],0xf0 (0xff)    
    jmp [esp-4]

     Since it's possible for returns to have a form that adds an immediate to
     the stack pointer, I need a more complicated form:
    xchg eax,[esp]
    test byte ptr [eax], 0x3
      (or test byte ptr [eax+0x40000000], 0x3 for fixed lookup offset)
    cmov(n)z eax, [eax]
      (OR cmov(n)z eax,[eax+0x40000000] for fixed lookup offset, pushed to
       next chunk for fixed lookup offset
       TODO: If fixed lookup offset code is changed back, I need to change the
       offset for modifying the 16-bit offset in the following chunk!)
    ---                      (chunk boundary)
    xchg [esp],eax
    add esp,0xffff <-replace this with 16-bit offset from return
    ---                      (chunk boundary)
    and byte ptr [esp-0xffff], 0xf0 (0xff) <-replace 0xffff w/ offs from ret
    jmp dword ptr [esp-0xffff] <-replace 0xffff with 16-bit offset from ret


  */ 
#ifdef PUSH_OLD_ADDRESSES
  if( *(insn->bytes) != RET_NEAR_IMM ){
    /* Conditionally load mapping entry */
    gen_padding(code,insn,sizeof(pop_jmp_template)-1);
    check_target(code,insn);
    memcpy(code->code+code->offset, pop_jmp_template,
        sizeof(pop_jmp_template)-1);
    code->offset += sizeof(pop_jmp_template)-1;

    /* Conditional mov is in separate chunk for fixed lookup offset */
    gen_padding(code,insn,sizeof(pop_jmp_template2)-1);
    memcpy(code->code+code->offset, pop_jmp_template2,
        sizeof(pop_jmp_template2)-1);
    code->offset += sizeof(pop_jmp_template2)-1;

    /* Mask address regardless of source (in new chunk) */
    gen_padding(code,insn,sizeof(pop_jmp_template_mask)-1);
    memcpy(code->code+code->offset, pop_jmp_template_mask,
        sizeof(pop_jmp_template_mask)-1);
    code->offset += sizeof(pop_jmp_template_mask)-1;
  }else{
    /* Conditionally load mapping entry */
    gen_padding(code,insn,sizeof(pop_jmp_imm_template)-1);
    check_target(code,insn);
    memcpy(code->code+code->offset, pop_jmp_imm_template,
        sizeof(pop_jmp_imm_template)-1);
    code->offset += sizeof(pop_jmp_imm_template)-1;
    
    /* Adjust stack pointer */
    gen_padding(code,insn,sizeof(pop_jmp_imm_template2)-1);
    memcpy(code->code+code->offset, pop_jmp_imm_template2,
        sizeof(pop_jmp_imm_template2)-1);
    /* Patch add instr with immediate value from ret <imm> */
    /* We need to add 4 to the immediate to include the additional 4 bytes
       that would have been added to $esp by ret for the return address.
       TODO: In theory adding 4 to the immediate could cause the immediate to
       overflow if it is almost 65535.  This edge case is not handled here. */
    /* We do not need to worry about the upper bits at all because ret <imm>
       appears to interpret the immediate as unsigned, so we can always leave
       the upper bits zero */
    *(uint16_t*)(code->code+code->offset+12) = 4 + *(uint16_t*)(insn->bytes+1);
    code->offset += sizeof(pop_jmp_imm_template2)-1;
    
    /* Mask address regardless of source (in new chunk) */
    gen_padding(code,insn,sizeof(pop_jmp_imm_template_mask)-1);
    memcpy(code->code+code->offset, pop_jmp_imm_template_mask,
        sizeof(pop_jmp_imm_template_mask)-1);
    /* Patch and instr and jmp instr with immediate value from ret <imm> */
    /* We need to add 4 to the immediate to include the additional 4 bytes
       that would have been added to $esp by ret for the return address.
       TODO: In theory adding 4 to the immediate could cause the immediate to
       overflow if it is almost 65535.  This edge case is not handled here. */
    /* Since both of these are SUBTRACTING from $esp, we need to get the
       2's complement of the immediate, and the upper bits will always be
       set. */
    *(uint16_t*)(code->code+code->offset+3) = -(4+*(uint16_t*)(insn->bytes+1));
    *(uint16_t*)(code->code+code->offset+11) = -(4+*(uint16_t*)(insn->bytes+1));
    code->offset += sizeof(pop_jmp_imm_template_mask)-1;
  }
#else
  size_t ret_size = 1;
  if( *(insn->bytes) == RET_NEAR_IMM ){
    ret_size = 3;
  }

  /* Conditionally load mapping entry */
  gen_padding(code, insn, sizeof(ret_template)-1);
  check_target(code, insn);
  memcpy(code->code+code->offset, ret_template, sizeof(ret_template)-1);
  code->offset += sizeof(ret_template)-1;
  
  /* Mask address regardless of source (in new chunk) */
  gen_padding(code, insn, sizeof(ret_template_mask)-1+ret_size);
  memcpy(code->code+code->offset,ret_template_mask,sizeof(ret_template_mask)-1);
  code->offset += sizeof(ret_template_mask)-1;
  
  /* copy return instruction over */
  memcpy( code->code+code->offset, insn->bytes, ret_size);
  code->offset += ret_size;
#endif
  code->last_safe_offset = code->offset;
  code->last_safe_reloc = code->reloc_count;
}
#else
inline void gen_ret(mv_code_t *code, ss_insn *insn){
  size_t new_code_size = 8;
  //printf("RET: %llx %s\n", insn->address, insn->insn_str);
  /* TODO: Handle far returns */
  if( *(insn->bytes) == RET_NEAR || *(insn->bytes) == RET_NEAR_IMM ){
     if( *(insn->bytes) == RET_NEAR_IMM ){
       new_code_size = 10;
     }
     /* Mask value at esp (the return address) to ensure return can only go to aligned chunk */
     gen_padding(code, insn, new_code_size); 
     check_target(code, insn);
     *(code->code+code->offset) = 0x81;// AND r/m32, imm 32
     *(code->code+code->offset+1) = 0x24;// r/m byte
     *(code->code+code->offset+2) = 0x24;// sib byte
     *(uintptr_t*)(code->code+code->offset+3) = code->mask;// immediate value holds mask
     if( *(insn->bytes) == RET_NEAR ){
       // place ret instruction after masking
       *(code->code+code->offset+7) = RET_NEAR;
     }else{
       // If RET_NEAR_IMM
       // place ret <imm> instruction after masking
       // Copy 3 bytes of return instruction encoding: c2 XX XX
       memcpy( code->code+code->offset+7, insn->bytes, 3);
     }
     code->offset += new_code_size; // Size of and+ret instruction pair  
     code->last_safe_offset = code->offset;
     code->last_safe_reloc = code->reloc_count;
  }
}
#endif // End check for DO_RET_LOOKUPS

inline void gen_cond(mv_code_t *code, ss_insn *insn){
  int32_t disp;
  
  /* TODO: Handle size prefixes (that switch 32-bit argument to 16-bit argument) */
  if( *(insn->bytes) == JCC_REL_NEAR  ){
    /* JCC with 4-byte offset (6-byte instruction) */
    gen_padding(code, insn, 6); 
    check_target(code, insn);
    /* Write instruction opcode in manually instead of using memcpy call */
    *(code->code+code->offset) = JCC_REL_NEAR;
    *(code->code+code->offset+1) = *(insn->bytes+1);
    disp = *(int32_t*)(insn->bytes+2);
    gen_reloc(code, RELOC_OFF, code->offset+2, insn->address+6+disp);
    code->offset += 6;
  }else{
    /* JCC with 1-byte offset (2-byte instruction) */
    gen_padding(code, insn, 6); 
    check_target(code, insn);
    /* Do not need to copy instruction bytes here because we will be writing the opcode manually.
       The bytes past the opcode will be patched in the relocation entry pass. */
    disp = *(int8_t*)(insn->bytes+1);
    /* Rewrite instruction to use long form.  TODO: This does NOT WORK for JCXZ/JECXZ/JRCXZ */
    /* The second byte of the long-form instructions is the same as the first byte of the
       short instructions, except the first half-byte is incremented by 1. */
    *(code->code+code->offset) = JCC_REL_NEAR;
    *(code->code+code->offset+1) = *(insn->bytes) + 0x10;
    gen_reloc(code, RELOC_OFF, code->offset+2, insn->address+2+disp);
    code->offset += 6; // Size of new, larger instruction
  }
}

inline void gen_uncond(mv_code_t *code, ss_insn *insn){
  int32_t disp;
  
  /* TODO: Handle size prefixes (that switch 32-bit argument to 16-bit argument) */
  switch( *(insn->bytes) ){
    /* Jump with 4-byte offset (5-byte instruction) */
    case JMP_REL_NEAR:
      /* Save last safe data before the CALL_REL_NEAR case because code after a call is executed */
      /* TODO: I think that this makes an incorrect assumption about the
         number of relocations, as it's possible for 2 to be generated,
	 AND actually the code offset can be increased by much more than 5
         due to alignment.  I think this must be moved AFTER code->offset and
         code->reloc_count have been set. */
    /* Call with 4-byte offset (5-byte instruction) - Same behavior as jump, so fall through */
    case CALL_REL_NEAR:
      /* Retrieve jmp target offset and add to relocation table */
      disp = *(int32_t*)(insn->bytes+1);
      /* Special case code for call to PIC, specifically the get_pc_thunk
         pattern. If call to PIC, we need to push original ret address to
         pass to thunk, then after thunk returns, move stack back to where
         it was before */
      /* If PUSH_OLD_ADDRESSES is defined, we don't need special case handling
         for pic because we are ALWAYS pushing the old address.  Pic code should
         work by default in that case. */
#ifdef PUSH_OLD_ADDRESSES
      if( *(insn->bytes) == CALL_REL_NEAR ){
#else
      if( is_pic(code, insn->address + insn->size + disp) && *(insn->bytes) == CALL_REL_NEAR ){
#endif
        /* Accommodate extra 5 bytes from push, but since this is a call, do
           not include bytes from add; the padding will align the call to the
           end of a chunk, so the add
           will be safely at the start of the next chunk */
        gen_padding(code, insn, 10); 
        check_target(code, insn);
        *(code->code+code->offset) = 0x68; // push imm32
        *(uint32_t*)(code->code+code->offset+1) = insn->address + insn->size; // return address
#ifdef PUSH_OLD_ADDRESSES
        *(code->code+code->offset+5) = 0xe9; // jmp instead of call
        gen_reloc(code, RELOC_OFF, code->offset+6, insn->address+5+disp);
        code->offset += 10; // length of push + call
#else
        /* This makes assumptions that PIC code is following the conventions of
           get_pc_thunk and is unsuitable for general use */
        *(code->code+code->offset+5) = *(insn->bytes); // original call
        *(code->code+code->offset+10) = 0x83; // add
        *(code->code+code->offset+11) = 0xc4; // esp,
        *(code->code+code->offset+12) = 0x04; // 4
        gen_reloc(code, RELOC_OFF, code->offset+6, insn->address+5+disp);
        code->offset += 13; // length of push + call + add esp,4
#endif
        break;
      }
      gen_padding(code, insn, 5); 
      check_target(code, insn);
      *(code->code+code->offset) = *(insn->bytes);
      //disp = code->mapping[insn->address+disp-code->base] - code->offset;
      //memcpy(code->code+code->offset+1, disp, 4);
      //printf("Gen: %s\t(%llx + 5 + %x)\n", insn->insn_str, insn->address, disp);
      /* Relocation target is instruction address + instruction length + displacement */
      gen_reloc(code, RELOC_OFF, code->offset+1, insn->address+5+disp);
      code->offset += 5;
      /* If PUSH_OLD_ADDRESSES is set and we are here, then the instruction is
         definitely a jmp and therefore we don't need to bother checking */ 
#ifndef PUSH_OLD_ADDRESSES
      if( *(insn->bytes) == JMP_REL_NEAR )
#endif
      {
        code->last_safe_offset = code->offset;
        code->last_safe_reloc = code->reloc_count;
      }
      break;
    /* Jump with 1-byte offset (2-byte instruction) */
    case JMP_REL_SHORT:
      gen_padding(code, insn, 5); 
      check_target(code, insn);
      /* Special case where we must extend the instruction to its longer form */
      disp = *(int8_t*)(insn->bytes+1);
      /* Patch initial byte of instruction from short jmp to near jmp */
      *(code->code+code->offset) = JMP_REL_NEAR;
      /* Relocation target is instruction address + instruction length + displacement */
      gen_reloc(code, RELOC_OFF, code->offset+1, insn->address+2+disp);
      /* TODO: special case where we must extend the instruction to its longer form */
      code->offset += 5; // Size of new, larger instruction
      code->last_safe_offset = code->offset;
      code->last_safe_reloc = code->reloc_count;
      break;
    case CALL_JMP_INDIRECT:
      gen_indirect(code, insn);
      break;
  }
}

void gen_indirect(mv_code_t *code, ss_insn *insn){
  //printf("INDIRECT: %llx %s\n", insn->address, insn->insn_str);
  /* TODO: This does not handle
       target in esp
       overlapping pointers
       optimizations for targets in registers
       what is the PROPER value we should have for the mask??
       why mask the top bits?  That breaks any code at a high address,
       which appears in real programs!
  */
  /*
    push eax
    mov eax, <MOD/RM>
    ---
    test byte ptr [eax], 3
      (OR test byte ptr [eax+0x40000000], 3 for fixed lookup offset)
    cmovnz eax, [eax]
      (OR cmov(n)z eax,[eax+0x40000000] for fixed lookup offset)
    ---
    ;and eax, 0x3FFFFFE0
    and eax, 0xFFFFFFF0   (and al, 0xFF for PUSH_OLD_ADDRESSES + TODO MASK )
    mov [esp-4],eax
      OR push eax, pop eax
    pop eax
    call/jmp [esp-8] 
      OR (if PUSH_OLD_ADDRESSES is defined):
        push <old return address>
        jmp [esp-4]
  */  
  /* This code does not fit cleanly into a single chunk, 
     so we need to split it into two pieces */
  /* While this padding is going to be excessive because it will notice the
     instruction is a CALL and will pad to the end of a chunk (there is
     no need to pad that much here because the second call to gen_padding
     further down is the one that requires padding to the end of a chunk),
     I think there's no harm in padding this way, as each half of this
     inserted code must be in two separate chunks anyway, and whether the code
     is at the start or end of a chunk shouldn't matter. */
  /* We subtract 1 from insn->size because we switch the first byte out from
     a jmp/call to a mov */
  gen_padding(code, insn, sizeof(indirect_template_before)-1 +
                          insn->size-1);
  check_target(code, insn);
  *(code->code+code->offset++) = indirect_template_before[0];
  *(code->code+code->offset++) = indirect_template_before[1];
  /* Copy Mod/RM byte from original instruction, but mask off /digit or REG:
     we can simply mask it off specifically because our target is eax,
     which is equivalent to /0 */
  *(code->code+code->offset++) = insn->bytes[1] & 0xC7;
  /* If instruction has a SIB byte or displacement, copy those over as well. */
  if( insn->size >= 3 ){
    memcpy( code->code+code->offset, insn->bytes+2, insn->size-2 );
    code->offset += insn->size-2;
  }
  gen_padding(code, insn, sizeof(indirect_template_after)-1); 
  memcpy( code->code+code->offset, indirect_template_after,
                                   sizeof(indirect_template_after)-1);
  code->offset += sizeof(indirect_template_after)-1;
  
  /* Second half */ 
#ifdef PUSH_OLD_ADDRESSES
  if( insn->id == SS_INS_CALL ){
    gen_padding(code, insn, sizeof(indirect_template_mask_push_jmp)-1);
    memcpy( code->code+code->offset, indirect_template_mask_push_jmp,
                                     sizeof(indirect_template_mask_push_jmp)-1);
    /* Patch template with return address from old code */
    *(uint32_t*)(code->code+code->offset+6) = insn->address + insn->size;
    code->offset += sizeof(indirect_template_mask_push_jmp)-1;
  }else{
    gen_padding(code, insn, sizeof(indirect_template_mask_jmp)-1);
    memcpy( code->code+code->offset, indirect_template_mask_jmp,
                                     sizeof(indirect_template_mask_jmp)-1);
    code->offset += sizeof(indirect_template_mask_jmp)-1;
  }
#else
  if( insn->id == SS_INS_CALL ){
    gen_padding(code, insn, sizeof(indirect_template_mask_call)-1);
    memcpy( code->code+code->offset, indirect_template_mask_call,
                                     sizeof(indirect_template_mask_call)-1);
    code->offset += sizeof(indirect_template_mask_call)-1;
  }else{
    gen_padding(code, insn, sizeof(indirect_template_mask_jmp)-1);
    memcpy( code->code+code->offset, indirect_template_mask_jmp,
                                     sizeof(indirect_template_mask_jmp)-1);
    code->offset += sizeof(indirect_template_mask_jmp)-1;
  }
#endif

  /* Generate a relocation entry to patch the ORIGINAL text section */
  /*gen_reloc(code, RELOC_IND, saved_off, insn->address);*/
  
  /* For a jump, we know that code can't fall through, so this offset is safe,
     i.e., we can assume it is plausibly real code */
  if( insn->id == SS_INS_JMP ){
    code->last_safe_offset = code->offset;
    code->last_safe_reloc = code->reloc_count;
  }
  
}

void gen_padding(mv_code_t *code, ss_insn *insn, uint16_t new_size){
  if( new_size > code->chunk_size ){
    printf("WARNING: Size of %d too large to fit in chunk!\n", new_size);
  }
  bool is_target = code->is_target(insn->address, (uint8_t*)(uintptr_t)insn->address, code->base, code->orig_size);
#ifdef DO_RET_LOOKUPS
  if( code->was_prev_inst_call ){
    is_target = true;
  }
#endif
  /* If we have selected a chunk size that is not zero AND the instruction is not already aligned,
     pad to chunk size whenever we encounter either:
       -An instruction that does not evenly fit within a chunk.
       -An instruction determined to be an indirect jump target by the is_target callback
    Fill the padded area with NOP instructions.
  */
  if( code->chunk_size != 0 && code->offset % code->chunk_size != 0 &&
      ( (is_target) ||
      (code->chunk_size - (code->offset % code->chunk_size) < new_size) ) ){
    memset(code->code+code->offset, NOP, code->chunk_size - (code->offset % code->chunk_size));
    code->offset += code->chunk_size - (code->offset % code->chunk_size);
  }
  /* If we have a nonzero chunk size, then we need to ensure all call
     instructions are padded to right before the end of a chunk.
  */
  if( code->chunk_size != 0 && (insn->id == SS_INS_CALL) &&
      ( (code->offset + new_size) % code->chunk_size != 0) ){
    memset(code->code+code->offset, NOP,
      code->chunk_size - ((code->offset + new_size) % code->chunk_size));
    code->offset += code->chunk_size - ((code->offset + new_size) % code->chunk_size);
  }
}

void check_target(mv_code_t *code, ss_insn *insn){
  bool is_target = code->is_target(insn->address, (uint8_t*)(uintptr_t)insn->address, code->base, code->orig_size);
#ifdef DO_RET_LOOKUPS
  if( code->was_prev_inst_call ){
    is_target = true;
  }
#endif
  /* Check whether we have encountered this address before.  If we have, then
     this must be a special jmp, and we should not treat it as a target!
     TODO: The method of checking this is here is a heuristic that
     should be avoided!  I should explicitly pass info indicating the
     instruction is a special jmp! */
  if( insn->address-code->base > 0 && 
      code->mapping[insn->address-code->base] != 0 ){
    return;
  }
  /*
    Insert ONE extra nop if instruction is not call, is a target, and there
    isn't already a serviceable nop present at the start of the chunk, 
    so that all targets start with 0x90, a requirement of the way we plan
    to deal with jump targets.  Since call instructions are aligned to the
    END of a chunk and calls that are also targets have a chunk to themselves,
    we have plenty of nops already!
  */
  if( is_target ){
#ifdef DEBUG
    printf("Generating reloc for target @ 0x%x (0x%x)\n", (uintptr_t)(code->code+code->offset), (uintptr_t)(code->offset|0x00000003));
#endif
    /* At this point the offset had better be chunk-aligned for all non-call
       instructions, and the start of a chunk with a call should be nop. */
    if( insn->id != SS_INS_CALL ){
      assert( (code->offset & ~code->mask) == 0 );
    }else{
      /* TODO MASK: Restore original masking code */
      code->code[code->offset & code->mask] = TARGET_LABEL;
      assert( code->code[code->offset & code->mask]==TARGET_LABEL );
      // Cannot perform this assertion without knowing the true length of the
      // rewritten instruction, which is not passed to this function.  This
      // assertion fails because if the call instruction is an INDIRECT call,
      // the length differs wildly from the 5 bytes of a simple direct call.
      //assert( (code->offset & ~code->mask) == (uintptr_t)code->chunk_size-5 );
    }
    /* If instruction is a target, not a call, and there is no nop already,
       insert one nop */
    if( insn->id != SS_INS_CALL &&
        code->code[code->offset] != TARGET_LABEL ){
      *(code->code+code->offset++) = TARGET_LABEL;
    }
    /* Generate a relocation entry to patch the ORIGINAL text section at
       this target address */
    /* Subtract to get to chunk-aligned 0x90 */
    /* Set the bottom 2 bits of offset, which will be masked off. */
    /* TODO MASK: Restore original masking code */
    gen_reloc(code, RELOC_IND,
        (code->offset & code->mask)/*|0x00000003*/,
        insn->address);
    /* Set offset of instruction in mapping.  At this point, we have added all
       padding we should add before the start of an instruction, and generated
       any relocation we needed.  This will generate the same value for the
       mapping as for the relocation.  Mask the offset to match the reloc. */
    code->mapping[insn->address-code->base] = code->offset & code->mask;
  }else{
    /* Set offset of instruction in mapping.  Do not mask the offset, as the
       instruction may not be aligned if it is not a target */
    code->mapping[insn->address-code->base] = code->offset;
  }
}

void gen_reloc(mv_code_t *code, uint8_t type, uint32_t offset, uintptr_t target){
  // Re-allocate when running out of space for relocations
  if( (code->reloc_count-1) * sizeof(mv_reloc_t) >= code->reloc_mem.size ){
    page_realloc(&code->reloc_mem, code->reloc_mem.size * 2 );
    code->relocs = code->reloc_mem.address;
  }
  mv_reloc_t *reloc = (code->relocs + code->reloc_count);
  reloc->type = type;
  reloc->offset = offset;
  reloc->target = target;
  code->reloc_count++;
}

/* Sorts RELOC_IND relocations, and moves all RELOC_OFF relocations to the
   front of the list of relocs without sorting them.
   Call this after all relocs have been generated to allow relocs in trimmed
   code to be removed correctly.  Returns the index of the first
   RELOC_IND reloc.
*/
size_t sort_relocs(mv_code_t *code){
  size_t i,j,first_ind;
  uintptr_t mintarget;
  mv_reloc_t rtemp;
  first_ind = 0;
  if( code->reloc_count == 0 ){
    return 0;
  }
  for( i = 0; i < code->reloc_count; i++ ){
    /* Don't sort RELOC_OFF entries, but put them before all other entries */
    if( code->relocs[i].type == RELOC_OFF ){
      rtemp = code->relocs[i];
      code->relocs[i] = code->relocs[first_ind];
      code->relocs[first_ind] = rtemp;
      first_ind++;
    }
  }
  /* Sort other entries */
  for( i = first_ind; i < code->reloc_count-1; i++ ){
    mintarget = i;
    for( j = i+1; j < code->reloc_count; j++){
      if( code->relocs[j].target < code->relocs[mintarget].target /*||
          (code->relocs[j].target == code->relocs[mintarget].target &&
           code->relocs[j].offset < code->relocs[mintarget].offset)*/ ){
        mintarget = j;
      }
    }
    rtemp = code->relocs[i];
    code->relocs[i] = code->relocs[mintarget];
    code->relocs[mintarget] = rtemp;
  }
  return first_ind;
}

/* Hardcoded special case to handle get_pc_thunk.  This will not work for arbitrary PIC, but
   hopefully this will be sufficient for automatically generated PIC on Linux */
bool is_pic(mv_code_t *code, uintptr_t address){
  /* Check range, since some target addresses may be nonsense */
  /* Ensure that we leave an additional 4 bytes of space to avoid reading
     outside the original region */
  /* Encoding of "mov ecx,[esp] ; ret", which is the code in get_pc_thunk */
  if( address >= code->base && address < code->base + code->orig_size-4 && 
      *(uint32_t*)(address) == 0xc3240c8b ){
    return true;
  }
  return false;
}
