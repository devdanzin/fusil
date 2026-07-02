/* fusil_malloc_shim.c -- LD_PRELOAD allocation-failure injector.
 *
 * The protocol-level analogue of _testcapi.set_nomemory, but at the C malloc() layer, so it
 * reaches FOREIGN C-library allocations (HDF5, zstd, libxml2, openssl, ...) that set_nomemory
 * (which only hooks CPython's PyMem allocators) structurally cannot.
 *
 * Control API (call from Python via ctypes.CDLL(None)). Signature is a drop-in for
 * _testcapi.set_nomemory(start, stop):
 *   void fusil_malloc_arm(long start, long stop);
 *       Reset the allocation counter and fail allocations numbered [start, stop).
 *       stop <= 0 means "fail forever from start" (the legacy single-call semantics).
 *   void fusil_malloc_disarm(void);
 *       Stop failing allocations.
 *   long fusil_malloc_count(void);
 *       Allocations seen since the last arm (diagnostics).
 *
 * Deterministic + windowed, exactly like set_nomemory, so crashes stay replayable/dedup-able.
 *
 * Build: cc -shared -fPIC -O2 -o fusil_malloc_shim.so fusil_malloc_shim.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

/* Real allocator pointers, resolved lazily from the next object in the link chain. */
static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static int (*real_posix_memalign)(void **, size_t, size_t);
static void *(*real_aligned_alloc)(size_t, size_t);

/* Failure-injection state. armed is release/acquire-synchronised so the window params and the
 * counter reset are visible to other threads once they observe armed == 1. */
static atomic_int armed = 0;
static atomic_long alloc_counter = 0;
static long fail_start = 0;
static long fail_end = 0; /* [fail_start, fail_end) fails; LONG_MAX == fail forever */

/* Bootstrap arena for allocations made by dlsym() itself during initialisation (glibc's
 * dlsym may call calloc). Served before real_* are resolved; never freed (tiny, bounded). */
static char boot_buf[65536];
static size_t boot_off = 0;
static int initializing = 0;

static void *boot_alloc(size_t size)
{
    size = (size + 15u) & ~(size_t)15u; /* 16-byte align */
    if (boot_off + size > sizeof(boot_buf))
        return NULL;
    void *p = boot_buf + boot_off;
    boot_off += size;
    return p;
}

static int is_boot_ptr(const void *p)
{
    return (const char *)p >= boot_buf && (const char *)p < boot_buf + sizeof(boot_buf);
}

static void init_reals(void)
{
    initializing = 1;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
    initializing = 0;
}

/* Return 1 if the current allocation should be failed. Counts only while armed. */
static int should_fail(void)
{
    if (!atomic_load_explicit(&armed, memory_order_acquire))
        return 0;
    long n = atomic_fetch_add_explicit(&alloc_counter, 1, memory_order_relaxed);
    return n >= fail_start && n < fail_end;
}

/* --- Control API (exported) --- */
void fusil_malloc_arm(long start, long stop)
{
    fail_start = start;
    fail_end = (stop > 0) ? stop : LONG_MAX; /* set_nomemory(start, stop): stop is absolute */
    atomic_store_explicit(&alloc_counter, 0, memory_order_relaxed);
    atomic_store_explicit(&armed, 1, memory_order_release);
}

void fusil_malloc_disarm(void)
{
    atomic_store_explicit(&armed, 0, memory_order_release);
}

long fusil_malloc_count(void)
{
    return atomic_load_explicit(&alloc_counter, memory_order_relaxed);
}

/* --- Interposed allocators --- */
void *malloc(size_t size)
{
    if (!real_malloc) {
        if (initializing)
            return boot_alloc(size);
        init_reals();
    }
    if (should_fail()) {
        errno = ENOMEM;
        return NULL;
    }
    return real_malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
    if (!real_calloc) {
        if (initializing) {
            void *p = boot_alloc(nmemb * size);
            if (p)
                memset(p, 0, nmemb * size);
            return p;
        }
        init_reals();
    }
    if (should_fail()) {
        errno = ENOMEM;
        return NULL;
    }
    return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    if (!real_realloc) {
        if (initializing)
            return boot_alloc(size);
        init_reals();
    }
    if (is_boot_ptr(ptr)) {
        /* Was served from the bootstrap arena: migrate to a real allocation. */
        if (should_fail()) {
            errno = ENOMEM;
            return NULL;
        }
        void *p = real_malloc(size);
        if (p && ptr) {
            size_t avail = (size_t)((boot_buf + boot_off) - (char *)ptr);
            memcpy(p, ptr, size < avail ? size : avail);
        }
        return p;
    }
    if (should_fail()) {
        errno = ENOMEM;
        return NULL;
    }
    return real_realloc(ptr, size);
}

void free(void *ptr)
{
    if (is_boot_ptr(ptr))
        return; /* bootstrap arena is never freed */
    if (!real_free)
        init_reals();
    if (real_free)
        real_free(ptr);
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (!real_posix_memalign)
        init_reals();
    if (should_fail())
        return ENOMEM;
    return real_posix_memalign(memptr, alignment, size);
}

void *aligned_alloc(size_t alignment, size_t size)
{
    if (!real_aligned_alloc)
        init_reals();
    if (should_fail()) {
        errno = ENOMEM;
        return NULL;
    }
    return real_aligned_alloc(alignment, size);
}
