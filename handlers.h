#include <signal.h>
#include <inttypes.h>
#include <stdbool.h>
void register_handler(bool (*my_is_target)(uintptr_t address, uint8_t *bytes));
void *__real_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
int __real_mprotect(void *addr, size_t len, int prot);
void sigsegv_handler(int sig, siginfo_t *info, void *ucontext);
