#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <errno.h>

extern long ax_syscall(long n, ...); 
void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    long ret = ax_syscall(222, addr, len, prot, flags, fildes, off);
    if (ret < 0) {
        errno = -ret;
        return MAP_FAILED;
    }
    return (void *)ret;
}

int munmap(void *addr, size_t length)
{
    long ret = ax_syscall(215, addr, length);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags,
             ... /* void *new_address */)
{
    va_list ap;
    void *new_address = NULL;
    if (flags & MREMAP_FIXED) {
        va_start(ap, flags);
        new_address = va_arg(ap, void *);
        va_end(ap);
    }

    long ret = ax_syscall(216, old_address, old_size, new_size, flags, new_address);
    if (ret < 0) {
        errno = -ret;
        return MAP_FAILED;
    }
    
    return (void *)ret;
}

int mprotect(void *addr, size_t len, int prot)
{
    long ret = ax_syscall(226, addr, len, prot);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    
    return 0;
}

int madvise(void *addr, size_t len, int advice)
{
    long ret = ax_syscall(233, addr, len, advice);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    
    return 0;
}
