.intel_syntax noprefix

	.globl	load_miniverse_asm
	.type	load_miniverse_asm, @function
	.align 16
load_miniverse_asm:
  push ebx
  push edi
  // Open fd
  call mini_open
  // Mmap exec
  push eax
  push 0x0
  push eax
  push 0x2
  push 0x5
  push 0x9f70b
  push 0xdeadb000
  call mini_mmap
  add esp,24
  // Mmap data
  pop eax
  push eax
  push 0x9f000
  push eax
  push 0x2
  push 0x3
  push 0x14000
  push 0xdeb7b000
  call mini_mmap
  add esp,24
  // Memset bss to 0
  mov eax, 0xdeb8be38
  mov ecx, 0x31c8
  call mini_memset
  // Call register_handler
  // Doing some fiddling to avoid having to know offset of my_is_target
  // when assembling this module
  call pic2
pic2:
  pop eax
  lea ecx,my_is_target
  lea ebx,pic2
  sub ebx,ecx
  sub eax,ebx
  push eax
  mov eax, 0xdeae4fa1
  call eax
  pop eax
  // Close fd
  pop eax
  call mini_close
  pop edi
  pop ebx
  ret

miniverse_path:
  .ascii "/usr/local/bin/miniverse-standalone\0"

mini_open:
  call pic
pic:
  pop eax
  lea ebx,[pic-miniverse_path]
  sub eax,ebx
  mov edx, 0
  mov ecx, 0
  mov ebx, eax
  mov eax, 5
  int 0x80
  cmp eax,0
  jl mini_exit
  ret

mini_close:
  mov ebx, eax
  mov eax, 6
  int 0x80
  ret

mini_mmap:
  lea ebx, [esp+4]
  mov eax, 90
  int 0x80
  cmp eax, [esp+4]
  jne mini_exit
  ret

mini_memset:
  mov edi, eax 
  xor eax,eax
  rep stosb
  ret

mini_exit:
  mov eax, 1
  mov ebx, -1
  int 0x80
  hlt

// Used to set gs segment register,
// to fake TLS for stack canaries.
// Should only be used if this code is
// run before any normal program initialization.
// This does not actually work, due to setting GS not being supported
// in 32 bit mode.  So how IS it set?  Well, somehow GS is set before
// reaching the binary's entry point, so the kernel probably figures
// out whether it needs to set it by some data in the elf file.
mini_arch_prctl:
  mov ecx, 0xdeadc000 // set address one page into code segment (not writeable)
  mov ebx, 0x1001 // ARCH_SET_GS
  mov eax, 384 // arch_prctl
  int 0x80
  cmp eax, 0
  jne mini_exit
  ret

  
