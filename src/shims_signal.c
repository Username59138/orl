// SPDX-License-Identifier: GPL-3.0-or-later
// Signals and setjmp/longjmp. On LP64 bionic:
//   sigset_t         = one 64-bit word, bit (sig - 1)   (glibc: 128 bytes)
//   struct sigaction = { int sa_flags; handler; sigset_t sa_mask; restorer; }
//                      (glibc: handler, 128-byte mask, flags, restorer)
//   jmp_buf          = long[11]                         (glibc: 200 bytes)
// Handlers themselves are fine: the kernel passes siginfo_t and ucontext_t,
// and bionic uses the kernel layouts for both.

#define _GNU_SOURCE
#include "shims.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

typedef uint64_t b_sigset_t;

// Field names differ from POSIX: glibc defines sa_handler etc. as macros.
struct b_sigaction {
    int flags;
    void *handler; // sa_handler or sa_sigaction
    b_sigset_t mask;
    void (*restorer)(void);
};

static void to_host_set(sigset_t *h, b_sigset_t b) {
    sigemptyset(h);
    h->__val[0] = b;
}

static int bad_sig(int sig) {
    if (sig >= 1 && sig <= 64) return 0;
    errno = EINVAL;
    return 1;
}

static int b_sigemptyset(b_sigset_t *s) { *s = 0; return 0; }
static int b_sigfillset(b_sigset_t *s) { *s = ~(b_sigset_t)0; return 0; }
static int b_sigaddset(b_sigset_t *s, int sig) {
    if (bad_sig(sig)) return -1;
    *s |= (b_sigset_t)1 << (sig - 1);
    return 0;
}
static int b_sigdelset(b_sigset_t *s, int sig) {
    if (bad_sig(sig)) return -1;
    *s &= ~((b_sigset_t)1 << (sig - 1));
    return 0;
}
static int b_sigismember(const b_sigset_t *s, int sig) {
    if (bad_sig(sig)) return -1;
    return (*s >> (sig - 1)) & 1;
}

static int b_pthread_sigmask(int how, const b_sigset_t *set, b_sigset_t *old) {
    sigset_t hs, ho;
    if (set) to_host_set(&hs, *set);
    int r = pthread_sigmask(how, set ? &hs : NULL, old ? &ho : NULL);
    if (r == 0 && old) *old = ho.__val[0];
    return r;
}

static int b_sigaction(int sig, const struct b_sigaction *act, struct b_sigaction *old) {
    struct sigaction ha, ho;
    if (act) {
        memset(&ha, 0, sizeof ha);
        ha.sa_handler = (__sighandler_t)act->handler;
        to_host_set(&ha.sa_mask, act->mask);
        ha.sa_flags = act->flags & ~SA_RESTORER; // glibc supplies its own
    }
    int r = sigaction(sig, act ? &ha : NULL, old ? &ho : NULL);
    if (r == 0 && old) {
        old->flags = ho.sa_flags & ~SA_RESTORER;
        old->handler = (void *)ho.sa_handler;
        old->mask = ho.sa_mask.__val[0];
        old->restorer = NULL;
    }
    return r;
}

/* ------------------------------------------------------- setjmp/longjmp --- */
// Our own layout inside bionic's long[11]:
//   [0..5] rbx rbp r12 r13 r14 r15   [6] rsp   [7] return address
//   [8] saved signal mask            [9] 1 if [8] is valid
// setjmp saves the mask (BSD semantics, like bionic), _setjmp doesn't,
// sigsetjmp decides by its argument. Every longjmp variant restores the mask
// exactly when it was saved. The mask goes through the raw syscall, which is
// what bionic does as well.

#define HIDDEN __attribute__((visibility("hidden")))
HIDDEN int b_setjmp(long *env);
HIDDEN int b__setjmp(long *env);
HIDDEN int b_sigsetjmp(long *env, int save_mask);
HIDDEN void b_longjmp(long *env, int val);
HIDDEN void b__longjmp(long *env, int val);
HIDDEN void b_siglongjmp(long *env, int val);

__asm__(
    ".text\n"
    ".globl b_setjmp, b__setjmp, b_sigsetjmp, b_longjmp, b__longjmp, b_siglongjmp\n"
    ".hidden b_setjmp, b__setjmp, b_sigsetjmp, b_longjmp, b__longjmp, b_siglongjmp\n"
    ".type b_setjmp, @function\n"
    "b_setjmp:\n"
    "    movl $1, %esi\n"
    "    jmp b_sigsetjmp\n"
    ".size b_setjmp, .-b_setjmp\n"

    ".type b__setjmp, @function\n"
    "b__setjmp:\n"
    "    xorl %esi, %esi\n"
    "    jmp b_sigsetjmp\n"
    ".size b__setjmp, .-b__setjmp\n"

    ".type b_sigsetjmp, @function\n"
    "b_sigsetjmp:\n"
    "    movq %rbx, 0(%rdi)\n"
    "    movq %rbp, 8(%rdi)\n"
    "    movq %r12, 16(%rdi)\n"
    "    movq %r13, 24(%rdi)\n"
    "    movq %r14, 32(%rdi)\n"
    "    movq %r15, 40(%rdi)\n"
    "    leaq 8(%rsp), %rdx\n"          // caller's rsp after we return
    "    movq %rdx, 48(%rdi)\n"
    "    movq (%rsp), %rdx\n"           // return address
    "    movq %rdx, 56(%rdi)\n"
    "    xorl %eax, %eax\n"
    "    testl %esi, %esi\n"
    "    setnz %al\n"
    "    movq %rax, 72(%rdi)\n"
    "    jz 1f\n"
    "    leaq 64(%rdi), %rdx\n"         // rt_sigprocmask(SIG_BLOCK, NULL, &env[8], 8)
    "    xorl %esi, %esi\n"
    "    xorl %edi, %edi\n"
    "    movl $8, %r10d\n"
    "    movl $14, %eax\n"
    "    syscall\n"
    "1:  xorl %eax, %eax\n"
    "    ret\n"
    ".size b_sigsetjmp, .-b_sigsetjmp\n"

    ".type b_longjmp, @function\n"
    ".type b__longjmp, @function\n"
    ".type b_siglongjmp, @function\n"
    "b_longjmp:\n"
    "b__longjmp:\n"
    "b_siglongjmp:\n"
    "    movq %rdi, %r9\n"
    "    movl %esi, %r8d\n"
    "    cmpq $0, 72(%rdi)\n"
    "    je 1f\n"
    "    leaq 64(%rdi), %rsi\n"         // rt_sigprocmask(SIG_SETMASK, &env[8], NULL, 8)
    "    xorl %edx, %edx\n"
    "    movl $2, %edi\n"
    "    movl $8, %r10d\n"
    "    movl $14, %eax\n"
    "    syscall\n"
    "    movq %r9, %rdi\n"
    "1:  movq 0(%rdi), %rbx\n"
    "    movq 8(%rdi), %rbp\n"
    "    movq 16(%rdi), %r12\n"
    "    movq 24(%rdi), %r13\n"
    "    movq 32(%rdi), %r14\n"
    "    movq 40(%rdi), %r15\n"
    "    movq 48(%rdi), %rsp\n"
    "    movl %r8d, %eax\n"
    "    testl %eax, %eax\n"            // longjmp(env, 0) returns 1
    "    jnz 2f\n"
    "    incl %eax\n"
    "2:  jmpq *56(%rdi)\n"
    ".size b_longjmp, .-b_longjmp\n"
);

const shim_entry shims_signal[] = {
    SHIM(sigemptyset), SHIM(sigfillset), SHIM(sigaddset), SHIM(sigdelset), SHIM(sigismember),
    SHIM(pthread_sigmask), SHIM(sigaction),
    SHIM(setjmp), SHIM(_setjmp), SHIM(sigsetjmp),
    SHIM(longjmp), SHIM(_longjmp), SHIM(siglongjmp),
    { NULL, NULL }
};
