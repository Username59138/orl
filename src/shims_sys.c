// SPDX-License-Identifier: GPL-3.0-or-later
// Assorted libc functions whose ABI differs between bionic and glibc:
// sysconf numbering, mallinfo, termios, semaphores, locales, long double,
// and bionic's static mutex initializers.

#define _GNU_SOURCE
#include "shims.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <locale.h>
#include <malloc.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

/* -------------------------------------------------------------- sysconf --- */
// bionic numbers _SC_* differently. Table generated from bionic's
// bits/sysconf.h: { bionic value, glibc name } for every name glibc has.

static const struct { int b, h; } sc_names[] = {
    { 0x0000, _SC_ARG_MAX }, { 0x0001, _SC_BC_BASE_MAX }, { 0x0002, _SC_BC_DIM_MAX },
    { 0x0003, _SC_BC_SCALE_MAX }, { 0x0004, _SC_BC_STRING_MAX }, { 0x0005, _SC_CHILD_MAX },
    { 0x0006, _SC_CLK_TCK }, { 0x0007, _SC_COLL_WEIGHTS_MAX }, { 0x0008, _SC_EXPR_NEST_MAX },
    { 0x0009, _SC_LINE_MAX }, { 0x000a, _SC_NGROUPS_MAX }, { 0x000b, _SC_OPEN_MAX },
    { 0x000c, _SC_PASS_MAX }, { 0x000d, _SC_2_C_BIND }, { 0x000e, _SC_2_C_DEV },
    { 0x000f, _SC_2_C_VERSION }, { 0x0010, _SC_2_CHAR_TERM }, { 0x0011, _SC_2_FORT_DEV },
    { 0x0012, _SC_2_FORT_RUN }, { 0x0013, _SC_2_LOCALEDEF }, { 0x0014, _SC_2_SW_DEV },
    { 0x0015, _SC_2_UPE }, { 0x0016, _SC_2_VERSION }, { 0x0017, _SC_JOB_CONTROL },
    { 0x0018, _SC_SAVED_IDS }, { 0x0019, _SC_VERSION }, { 0x001a, _SC_RE_DUP_MAX },
    { 0x001b, _SC_STREAM_MAX }, { 0x001c, _SC_TZNAME_MAX }, { 0x001d, _SC_XOPEN_CRYPT },
    { 0x001e, _SC_XOPEN_ENH_I18N }, { 0x001f, _SC_XOPEN_SHM }, { 0x0020, _SC_XOPEN_VERSION },
    { 0x0021, _SC_XOPEN_XCU_VERSION }, { 0x0022, _SC_XOPEN_REALTIME }, { 0x0023, _SC_XOPEN_REALTIME_THREADS },
    { 0x0024, _SC_XOPEN_LEGACY }, { 0x0025, _SC_ATEXIT_MAX }, { 0x0026, _SC_IOV_MAX },
    { 0x0027, _SC_PAGESIZE }, { 0x0028, _SC_PAGE_SIZE }, { 0x0029, _SC_XOPEN_UNIX },
    { 0x002a, _SC_XBS5_ILP32_OFF32 }, { 0x002b, _SC_XBS5_ILP32_OFFBIG }, { 0x002c, _SC_XBS5_LP64_OFF64 },
    { 0x002d, _SC_XBS5_LPBIG_OFFBIG }, { 0x002e, _SC_AIO_LISTIO_MAX }, { 0x002f, _SC_AIO_MAX },
    { 0x0030, _SC_AIO_PRIO_DELTA_MAX }, { 0x0031, _SC_DELAYTIMER_MAX }, { 0x0032, _SC_MQ_OPEN_MAX },
    { 0x0033, _SC_MQ_PRIO_MAX }, { 0x0034, _SC_RTSIG_MAX }, { 0x0035, _SC_SEM_NSEMS_MAX },
    { 0x0036, _SC_SEM_VALUE_MAX }, { 0x0037, _SC_SIGQUEUE_MAX }, { 0x0038, _SC_TIMER_MAX },
    { 0x0039, _SC_ASYNCHRONOUS_IO }, { 0x003a, _SC_FSYNC }, { 0x003b, _SC_MAPPED_FILES },
    { 0x003c, _SC_MEMLOCK }, { 0x003d, _SC_MEMLOCK_RANGE }, { 0x003e, _SC_MEMORY_PROTECTION },
    { 0x003f, _SC_MESSAGE_PASSING }, { 0x0040, _SC_PRIORITIZED_IO }, { 0x0041, _SC_PRIORITY_SCHEDULING },
    { 0x0042, _SC_REALTIME_SIGNALS }, { 0x0043, _SC_SEMAPHORES }, { 0x0044, _SC_SHARED_MEMORY_OBJECTS },
    { 0x0045, _SC_SYNCHRONIZED_IO }, { 0x0046, _SC_TIMERS }, { 0x0047, _SC_GETGR_R_SIZE_MAX },
    { 0x0048, _SC_GETPW_R_SIZE_MAX }, { 0x0049, _SC_LOGIN_NAME_MAX }, { 0x004a, _SC_THREAD_DESTRUCTOR_ITERATIONS },
    { 0x004b, _SC_THREAD_KEYS_MAX }, { 0x004c, _SC_THREAD_STACK_MIN }, { 0x004d, _SC_THREAD_THREADS_MAX },
    { 0x004e, _SC_TTY_NAME_MAX }, { 0x004f, _SC_THREADS }, { 0x0050, _SC_THREAD_ATTR_STACKADDR },
    { 0x0051, _SC_THREAD_ATTR_STACKSIZE }, { 0x0052, _SC_THREAD_PRIORITY_SCHEDULING }, { 0x0053, _SC_THREAD_PRIO_INHERIT },
    { 0x0054, _SC_THREAD_PRIO_PROTECT }, { 0x0055, _SC_THREAD_SAFE_FUNCTIONS }, { 0x0060, _SC_NPROCESSORS_CONF },
    { 0x0061, _SC_NPROCESSORS_ONLN }, { 0x0062, _SC_PHYS_PAGES }, { 0x0063, _SC_AVPHYS_PAGES },
    { 0x0064, _SC_MONOTONIC_CLOCK }, { 0x0065, _SC_2_PBS }, { 0x0066, _SC_2_PBS_ACCOUNTING },
    { 0x0067, _SC_2_PBS_CHECKPOINT }, { 0x0068, _SC_2_PBS_LOCATE }, { 0x0069, _SC_2_PBS_MESSAGE },
    { 0x006a, _SC_2_PBS_TRACK }, { 0x006b, _SC_ADVISORY_INFO }, { 0x006c, _SC_BARRIERS },
    { 0x006d, _SC_CLOCK_SELECTION }, { 0x006e, _SC_CPUTIME }, { 0x006f, _SC_HOST_NAME_MAX },
    { 0x0070, _SC_IPV6 }, { 0x0071, _SC_RAW_SOCKETS }, { 0x0072, _SC_READER_WRITER_LOCKS },
    { 0x0073, _SC_REGEXP }, { 0x0074, _SC_SHELL }, { 0x0075, _SC_SPAWN },
    { 0x0076, _SC_SPIN_LOCKS }, { 0x0077, _SC_SPORADIC_SERVER }, { 0x0078, _SC_SS_REPL_MAX },
    { 0x0079, _SC_SYMLOOP_MAX }, { 0x007a, _SC_THREAD_CPUTIME }, { 0x007b, _SC_THREAD_PROCESS_SHARED },
    { 0x007c, _SC_THREAD_ROBUST_PRIO_INHERIT }, { 0x007d, _SC_THREAD_ROBUST_PRIO_PROTECT }, { 0x007e, _SC_THREAD_SPORADIC_SERVER },
    { 0x007f, _SC_TIMEOUTS }, { 0x0080, _SC_TRACE }, { 0x0081, _SC_TRACE_EVENT_FILTER },
    { 0x0082, _SC_TRACE_EVENT_NAME_MAX }, { 0x0083, _SC_TRACE_INHERIT }, { 0x0084, _SC_TRACE_LOG },
    { 0x0085, _SC_TRACE_NAME_MAX }, { 0x0086, _SC_TRACE_SYS_MAX }, { 0x0087, _SC_TRACE_USER_EVENT_MAX },
    { 0x0088, _SC_TYPED_MEMORY_OBJECTS }, { 0x0089, _SC_V7_ILP32_OFF32 }, { 0x008a, _SC_V7_ILP32_OFFBIG },
    { 0x008b, _SC_V7_LP64_OFF64 }, { 0x008c, _SC_V7_LPBIG_OFFBIG }, { 0x008d, _SC_XOPEN_STREAMS },
    { 0x008f, _SC_LEVEL1_ICACHE_SIZE }, { 0x0090, _SC_LEVEL1_ICACHE_ASSOC }, { 0x0091, _SC_LEVEL1_ICACHE_LINESIZE },
    { 0x0092, _SC_LEVEL1_DCACHE_SIZE }, { 0x0093, _SC_LEVEL1_DCACHE_ASSOC }, { 0x0094, _SC_LEVEL1_DCACHE_LINESIZE },
    { 0x0095, _SC_LEVEL2_CACHE_SIZE }, { 0x0096, _SC_LEVEL2_CACHE_ASSOC }, { 0x0097, _SC_LEVEL2_CACHE_LINESIZE },
    { 0x0098, _SC_LEVEL3_CACHE_SIZE }, { 0x0099, _SC_LEVEL3_CACHE_ASSOC }, { 0x009a, _SC_LEVEL3_CACHE_LINESIZE },
    { 0x009b, _SC_LEVEL4_CACHE_SIZE }, { 0x009c, _SC_LEVEL4_CACHE_ASSOC }, { 0x009d, _SC_LEVEL4_CACHE_LINESIZE },
};

static long b_sysconf(int name) {
    for (size_t i = 0; i < sizeof sc_names / sizeof sc_names[0]; i++)
        if (sc_names[i].b == name) return sysconf(sc_names[i].h);
    if (getenv("ORL_TRACE")) fprintf(stderr, "[shim] unknown sysconf 0x%x\n", name);
    errno = EINVAL;
    return -1;
}

/* ------------------------------------------------------------- mallinfo --- */
// bionic's struct mallinfo has size_t fields, i.e. it is glibc's mallinfo2.

static struct mallinfo2 b_mallinfo(void) { return mallinfo2(); }

/* -------------------------------------------------------------- termios --- */
// bionic's struct termios is the kernel's (36 bytes); glibc's is 60 bytes
// and its tcgetattr would write past the end. Talk to the kernel directly.

static int b_tcgetattr(int fd, void *t) { return ioctl(fd, TCGETS, t); }

static int b_tcsetattr(int fd, int action, const void *t) {
    unsigned long cmd;
    switch (action) {
    case TCSANOW:   cmd = TCSETS; break;
    case TCSADRAIN: cmd = TCSETSW; break;
    case TCSAFLUSH: cmd = TCSETSF; break;
    default: errno = EINVAL; return -1;
    }
    return ioctl(fd, cmd, t);
}

/* ----------------------------------------------------------- semaphores --- */
// bionic's sem_t is 16 bytes on LP64, glibc's is 32. Own futex counter:
// `count` plus the number of sleeping waiters, so sem_post only makes a
// syscall when someone actually waits.

#define B_SEM_VALUE_MAX 0x3fffffff
typedef struct {
    _Atomic unsigned count;
    _Atomic int waiters;
    int private_flag; // FUTEX_PRIVATE_FLAG unless process-shared
    int reserved;
} b_sem_t;
_Static_assert(sizeof(b_sem_t) == 16, "bionic sem_t");

static long futex(_Atomic unsigned *addr, int op, unsigned val) {
    return syscall(SYS_futex, addr, op, val, NULL, NULL, 0);
}

static int b_sem_init(b_sem_t *s, int pshared, unsigned value) {
    if (value > B_SEM_VALUE_MAX) { errno = EINVAL; return -1; }
    atomic_init(&s->count, value);
    atomic_init(&s->waiters, 0);
    s->private_flag = pshared ? 0 : FUTEX_PRIVATE_FLAG;
    s->reserved = 0;
    return 0;
}

static int b_sem_destroy(b_sem_t *s) { (void)s; return 0; }

static int b_sem_trywait(b_sem_t *s) {
    unsigned c = atomic_load(&s->count);
    while (c > 0)
        if (atomic_compare_exchange_weak(&s->count, &c, c - 1)) return 0;
    errno = EAGAIN;
    return -1;
}

static int b_sem_wait(b_sem_t *s) {
    for (;;) {
        if (b_sem_trywait(s) == 0) return 0;
        atomic_fetch_add(&s->waiters, 1);
        long r = futex(&s->count, FUTEX_WAIT | s->private_flag, 0);
        int e = errno;
        atomic_fetch_sub(&s->waiters, 1);
        if (r == -1 && e == EINTR) { errno = EINTR; return -1; } // API >= 24 behaviour
    }
}

static int b_sem_post(b_sem_t *s) {
    unsigned c = atomic_load(&s->count);
    do {
        if (c >= B_SEM_VALUE_MAX) { errno = EOVERFLOW; return -1; }
    } while (!atomic_compare_exchange_weak(&s->count, &c, c + 1));
    if (atomic_load(&s->waiters) > 0)
        futex(&s->count, FUTEX_WAKE | s->private_flag, 1);
    return 0;
}

static int b_sem_getvalue(b_sem_t *s, int *value) {
    *value = (int)atomic_load(&s->count);
    return 0;
}

/* -------------------------------------------------------------- locales --- */
// bionic only knows "", "C", "POSIX", "C.UTF-8" and "en_US.UTF-8", and all
// of them behave like C.UTF-8 (its wide-char functions always speak Unicode).
// It also ignores `base`, while glibc consumes it, so never pass it on.

static locale_t b_newlocale(int mask, const char *name, locale_t base) {
    (void)base;
    if (!name || (mask & ~LC_ALL_MASK)) { errno = EINVAL; return NULL; }
    static const char *const ok[] = { "", "C", "POSIX", "C.UTF-8", "en_US.UTF-8" };
    size_t i = 0;
    while (i < sizeof ok / sizeof ok[0] && strcmp(ok[i], name) != 0) i++;
    if (i == sizeof ok / sizeof ok[0]) { errno = ENOENT; return NULL; }
    locale_t l = newlocale(mask, "C.UTF-8", NULL);
    return l ? l : newlocale(mask, "C", NULL);
}

/* ---------------------------------------------------------- long double --- */
// Android x86_64 uses IEEE quad for long double (passed in SSE registers),
// glibc uses x87 80-bit. glibc's _Float128 functions are the quad ones.

static _Float128 b_strtold(const char *s, char **end) { return strtof128(s, end); }
static _Float128 b_strtold_l(const char *s, char **end, locale_t l) { return strtof128_l(s, end, l); }
static _Float128 b_powl(_Float128 x, _Float128 y) { return powf128(x, y); }
static _Float128 b_fmal(_Float128 x, _Float128 y, _Float128 z) { return fmaf128(x, y, z); }

/* --------------------------------------------------------------- mutexes --- */
// bionic's PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP / ..._ERRORCHECK_... put
// (type << 14) into the first word, which glibc would read as "locked".
// Turn such a mutex into a glibc one on first use: set the kind first, then
// clear the word, so every thread that sees it unlocked also sees the kind.
// (glibc never stores 0x4000/0x8000 there for the non-robust mutexes we make.)

static void fix_static_mutex(pthread_mutex_t *m) {
    _Atomic int *word = (_Atomic int *)(void *)m;
    int v = atomic_load_explicit(word, memory_order_relaxed);
    if (__builtin_expect(v != 0x4000 && v != 0x8000, 1)) return;
    int kind = v == 0x4000 ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_ERRORCHECK;
    int zero = 0;
    atomic_compare_exchange_strong((_Atomic int *)&m->__data.__kind, &zero, kind);
    atomic_compare_exchange_strong(word, &v, 0);
}

static int b_pthread_mutex_lock(pthread_mutex_t *m) {
    fix_static_mutex(m);
    return pthread_mutex_lock(m);
}
static int b_pthread_mutex_trylock(pthread_mutex_t *m) {
    fix_static_mutex(m);
    return pthread_mutex_trylock(m);
}

const shim_entry shims_sys[] = {
    SHIM(sysconf), SHIM(mallinfo), SHIM(tcgetattr), SHIM(tcsetattr),
    SHIM(sem_init), SHIM(sem_destroy), SHIM(sem_wait), SHIM(sem_trywait), SHIM(sem_post),
    SHIM(sem_getvalue),
    SHIM(newlocale),
    SHIM(strtold), SHIM(strtold_l), SHIM(powl), SHIM(fmal),
    SHIM(pthread_mutex_lock), SHIM(pthread_mutex_trylock),
    { NULL, NULL }
};
