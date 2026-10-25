// SPDX-License-Identifier: GPL-3.0-or-later
// Checks the shims whose ABI differs between bionic and glibc. Built with
// --target=x86_64-linux-android26 and -nostdlib, so every type below has
// its bionic layout and every call goes through our loader's bindings.
// Declarations are written by hand from bionic's headers.

typedef unsigned long size_t;
typedef unsigned long sigset_t; // LP64 bionic: one word
typedef long jmp_buf[11];

_Static_assert(__LDBL_MANT_DIG__ == 113, "Android x86_64 long double is IEEE quad");

extern int __android_log_print(int prio, const char *tag, const char *fmt, ...);
extern int *__errno(void);
extern int strcmp(const char *, const char *);
extern char *strstr(const char *, const char *);
extern void *malloc(size_t);
extern void free(void *);
extern int getpagesize(void);

// stdio
extern char __sF[]; // struct __sFILE[3], 152 bytes each
extern int fprintf(void *fp, const char *fmt, ...);
extern int fflush(void *fp);
extern int fileno(void *fp);

// unistd / string / malloc
extern long sysconf(int name);
extern int strerror_r(int e, char *buf, size_t n);
struct mallinfo { size_t arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks,
                  uordblks, fordblks, keepcost; };
extern struct mallinfo mallinfo(void);
extern void __FD_SET_chk(int fd, unsigned long *set, size_t size);
extern int __FD_ISSET_chk(int fd, const unsigned long *set, size_t size);
extern int tcgetattr(int fd, void *termios);

// signals, setjmp
struct sigaction { int sa_flags; void (*sa_handler)(int); sigset_t sa_mask; void (*sa_restorer)(void); };
extern int sigemptyset(sigset_t *);
extern int sigaddset(sigset_t *, int);
extern int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
extern int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
extern int raise(int sig);
__attribute__((returns_twice)) extern int setjmp(jmp_buf);
__attribute__((returns_twice)) extern int _setjmp(jmp_buf);
__attribute__((noreturn)) extern void longjmp(jmp_buf, int);
__attribute__((noreturn)) extern void _longjmp(jmp_buf, int);

// netdb
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct addrinfo { int ai_flags, ai_family, ai_socktype, ai_protocol; unsigned ai_addrlen;
                  char *ai_canonname; struct sockaddr *ai_addr; struct addrinfo *ai_next; };
extern int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
extern void freeaddrinfo(struct addrinfo *);
extern const char *gai_strerror(int);

// semaphores, mutexes
typedef struct { unsigned count; int reserved[3]; } sem_t;
extern int sem_init(sem_t *, int, unsigned);
extern int sem_destroy(sem_t *);
extern int sem_wait(sem_t *);
extern int sem_trywait(sem_t *);
extern int sem_post(sem_t *);
extern int sem_getvalue(sem_t *, int *);
typedef struct { int words[10]; } pthread_mutex_t;
extern int pthread_mutex_lock(pthread_mutex_t *);
extern int pthread_mutex_unlock(pthread_mutex_t *);

// locales, multibyte, long double
typedef void *locale_t;
typedef struct { unsigned char seq[4], reserved[4]; } mbstate_t;
extern locale_t newlocale(int mask, const char *name, locale_t base);
extern void freelocale(locale_t);
extern size_t mbrtowc(int *wc, const char *s, size_t n, mbstate_t *st);
extern long double strtold_l(const char *, char **, locale_t);
extern long double powl(long double, long double);
extern long double fmal(long double, long double, long double);

// dl
typedef struct { const char *fname; void *fbase; const char *sname; void *saddr; } Dl_info;
struct dl_phdr_info { unsigned long addr; const char *name; const void *phdr; unsigned short phnum; };
extern int dladdr(const void *, Dl_info *);
extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern char *dlerror(void);
extern int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

#define SIGUSR1 10
#define SIGUSR2 12
#define BIT(sig) (1UL << ((sig) - 1))
#define LC_ALL_MASK 0x1fbf

static int failures;
#define CHECK(cond, what) do {                                                  \
        if (cond) __android_log_print(4, "testabi", "ok   %s", what);          \
        else { __android_log_print(6, "testabi", "FAIL %s", what); failures++; } \
    } while (0)

static void *stream(int n) { return __sF + 152 * n; }

static void test_stdio(void) {
    CHECK(fprintf(stream(2), "[testabi] written through &__sF[2]\n") > 0, "fprintf(&__sF[2])");
    CHECK(fflush(stream(2)) == 0, "fflush(&__sF[2])");
    CHECK(fileno(stream(1)) == 1 && fileno(stream(2)) == 2, "fileno(&__sF[1..2])");
}

static void test_libc(void) {
    char buf[128];
    CHECK(sysconf(0x27) == getpagesize(), "sysconf(_SC_PAGESIZE = 0x27)");
    CHECK(sysconf(0x61) >= 1, "sysconf(_SC_NPROCESSORS_ONLN = 0x61)");
    CHECK(strerror_r(2, buf, sizeof buf) == 0 && strcmp(buf, "No such file or directory") == 0,
          "strerror_r returns int (POSIX)");

    void *p = malloc(1000);
    struct mallinfo mi = mallinfo();
    CHECK(mi.uordblks >= 1000 && mi.uordblks < (size_t)1 << 40, "mallinfo has size_t fields");
    free(p);

    unsigned long fds[16] = { 0 };
    __FD_SET_chk(70, fds, sizeof fds);
    CHECK(fds[1] == 1UL << 6 && __FD_ISSET_chk(70, fds, sizeof fds), "__FD_SET_chk/__FD_ISSET_chk");

    struct { unsigned char t[36]; unsigned char canary[24]; } tio;
    for (int i = 0; i < 24; i++) tio.canary[i] = 0xAA;
    int r = tcgetattr(0, &tio);
    int intact = 1;
    for (int i = 0; i < 24; i++) intact &= tio.canary[i] == 0xAA;
    CHECK((r == 0 || *__errno() == 25 /* ENOTTY */) && intact, "tcgetattr writes 36 bytes only");
}

static volatile int usr1_hits;
static sigset_t mask_in_handler;
static void on_usr1(int sig) {
    (void)sig;
    usr1_hits++;
    pthread_sigmask(0, 0, &mask_in_handler);
}

static void test_signals(void) {
    struct { struct sigaction sa; unsigned long canary[4]; } old = { .canary = { 7, 7, 7, 7 } };
    struct sigaction sa = { .sa_handler = on_usr1, .sa_mask = BIT(SIGUSR2) };
    CHECK(sigaction(SIGUSR1, &sa, 0) == 0, "sigaction install");
    raise(SIGUSR1);
    CHECK(usr1_hits == 1, "handler ran");
    CHECK(mask_in_handler & BIT(SIGUSR2), "sa_mask applied inside handler");
    CHECK(sigaction(SIGUSR1, 0, &old.sa) == 0 && old.sa.sa_handler == on_usr1 &&
          (old.sa.sa_mask & BIT(SIGUSR2)) && old.canary[0] == 7 && old.canary[3] == 7,
          "sigaction reads back in bionic layout");

    static jmp_buf jb;
    sigset_t set, cur;
    sigemptyset(&set);
    pthread_sigmask(2, &set, 0);
    volatile int v = setjmp(jb);
    if (v == 0) {
        sigaddset(&set, SIGUSR2);
        pthread_sigmask(0, &set, 0);
        longjmp(jb, 0);
    }
    pthread_sigmask(0, 0, &cur);
    CHECK(v == 1, "longjmp(env, 0) makes setjmp return 1");
    CHECK(!(cur & BIT(SIGUSR2)), "longjmp restores the mask saved by setjmp");

    v = _setjmp(jb);
    if (v == 0) {
        pthread_sigmask(0, &set, 0);
        _longjmp(jb, 5);
    }
    pthread_sigmask(0, 0, &cur);
    CHECK(v == 5 && (cur & BIT(SIGUSR2)), "_setjmp/_longjmp leave the mask alone");
    sigemptyset(&set);
    pthread_sigmask(2, &set, 0);
}

static void test_netdb(void) {
    struct addrinfo hints = { .ai_flags = 4 | 8, .ai_socktype = 1 }, *res = 0;
    CHECK(getaddrinfo("127.0.0.1", "http", &hints, &res) == 8,
          "AI_NUMERICSERV mapped, EAI_NONAME = 8");
    hints.ai_flags = 2 | 4 | 8; // CANONNAME | NUMERICHOST | NUMERICSERV
    int r = getaddrinfo("127.0.0.1", "80", &hints, &res);
    CHECK(r == 0 && res, "getaddrinfo numeric");
    if (r == 0) {
        unsigned char *a = (unsigned char *)res->ai_addr;
        CHECK(res->ai_family == 2 && a && a[0] == 2 && a[2] == 0 && a[3] == 80 &&
              a[4] == 127 && a[7] == 1, "ai_addr in bionic position");
        CHECK(res->ai_canonname && strcmp(res->ai_canonname, "127.0.0.1") == 0,
              "ai_canonname in bionic position");
        CHECK(res->ai_flags == (2 | 4 | 8), "ai_flags in bionic values");
        freeaddrinfo(res);
    }
    hints.ai_flags = 0x800; // AI_V4MAPPED: bionic rejects it
    CHECK(getaddrinfo("127.0.0.1", "80", &hints, &res) == 3, "EAI_BADFLAGS = 3");
    CHECK(gai_strerror(8) && gai_strerror(8)[0], "gai_strerror(bionic code)");
}

static void test_sync(void) {
    sem_t s;
    int val = -1;
    CHECK(sem_init(&s, 0, 0) == 0, "sem_init");
    CHECK(sem_trywait(&s) == -1 && *__errno() == 11, "sem_trywait on 0 -> EAGAIN");
    sem_post(&s);
    CHECK(sem_getvalue(&s, &val) == 0 && val == 1, "sem_post / sem_getvalue");
    CHECK(sem_wait(&s) == 0, "sem_wait");
    sem_destroy(&s);

    pthread_mutex_t rec = { { 0x4000 } }; // PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
    CHECK(pthread_mutex_lock(&rec) == 0 && pthread_mutex_lock(&rec) == 0 &&
          pthread_mutex_unlock(&rec) == 0 && pthread_mutex_unlock(&rec) == 0,
          "static recursive mutex");
    pthread_mutex_t chk = { { 0x8000 } }; // PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
    CHECK(pthread_mutex_lock(&chk) == 0 && pthread_mutex_lock(&chk) == 35 /* EDEADLK */ &&
          pthread_mutex_unlock(&chk) == 0, "static errorcheck mutex");
}

static int quad_is(long double v, unsigned long hi, unsigned long lo) {
    union { long double v; unsigned long w[2]; } u = { v };
    return u.w[1] == hi && u.w[0] == lo;
}

static void test_locale(void) {
    locale_t l = newlocale(LC_ALL_MASK, "en_US.UTF-8", 0);
    CHECK(l != 0, "newlocale(en_US.UTF-8)");
    CHECK(newlocale(LC_ALL_MASK, "de_DE", 0) == 0 && *__errno() == 2, "newlocale(other) -> ENOENT");

    int wc = 0;
    mbstate_t st = { { 0 }, { 0 } };
    CHECK(mbrtowc(&wc, "\xc3\xa9", 2, &st) == 2 && wc == 0xe9, "mbrtowc decodes UTF-8");

    CHECK(quad_is(strtold_l("1.5", 0, l), 0x3fff800000000000UL, 0), "strtold_l returns quad");
    CHECK(quad_is(powl(2.0L, 10.0L), 0x4009000000000000UL, 0), "powl in quad");
    CHECK(quad_is(fmal(2.0L, 3.0L, 4.0L), 0x4002400000000000UL, 0), "fmal in quad");
    if (l) freelocale(l);
}

int abi_entry(const char *arg);

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (info->name && strstr(info->name, "testabi") && info->phnum > 0) {
        *(unsigned long *)data = info->addr;
        return 1;
    }
    return 0;
}

static void test_dl(void) {
    Dl_info di = { 0 };
    CHECK(dladdr((void *)abi_entry, &di) && di.sname && strcmp(di.sname, "abi_entry") == 0 &&
          strstr(di.fname, "testabi"), "dladdr knows our module");
    unsigned long base = 0;
    CHECK(dl_iterate_phdr(phdr_cb, &base) == 1 && base == (unsigned long)di.fbase,
          "dl_iterate_phdr reports our module");
    void *libc = dlopen("libc.so", 2);
    CHECK(libc && dlsym(libc, "sigaction") == (void *)sigaction, "dlsym(libc) returns the shim");
    CHECK(dlsym(0, "abi_entry") == (void *)abi_entry, "dlsym(RTLD_DEFAULT) finds our exports");
    CHECK(!dlopen("libnope.so", 2) && dlerror(), "dlopen of an unknown library fails");
}

int abi_entry(const char *arg) {
    (void)arg;
    test_stdio();
    test_libc();
    test_signals();
    test_netdb();
    test_sync();
    test_locale();
    test_dl();
    __android_log_print(4, "testabi", "%d failure(s)", failures);
    return failures;
}
