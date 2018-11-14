void mmap_hook(void *addr);
void mprotect_hook(void *addr);
void register_handler();
void *mmap_shim(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
int mprotect_shim(void *addr, size_t len, int prot);
void sigsegv_handler(int signum);
