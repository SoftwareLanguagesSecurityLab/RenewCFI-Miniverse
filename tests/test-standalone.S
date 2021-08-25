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
  push 0xb0b29
  push 0xdeadb000
  call mini_mmap
  add esp,24
  // Mmap data
  pop eax
  push eax
  push 0xb1000
  push eax
  push 0x2
  push 0x3
  push 0x11000
  push 0xdeb8d000
  call mini_mmap
  add esp,24
  // Memset bss to 0
  mov eax, 0xdeb9ceb8
  mov ecx, 0x1148
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
  mov eax, 0xdeae3d10
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
  sub eax,pic-miniverse_path
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
  
