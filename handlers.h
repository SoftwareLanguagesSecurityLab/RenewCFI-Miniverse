#include <signal.h>
void mmap_hook(void *addr);
void mprotect_hook(void *addr);
void register_handler();
void *__real_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
int __real_mprotect(void *addr, size_t len, int prot);
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext);
