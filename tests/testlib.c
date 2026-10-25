// SPDX-License-Identifier: GPL-3.0-or-later
// A stand-in for an Android library: built with -nostdlib so every libc /
// liblog call is an unresolved import that our loader has to bind, exactly
// like a bionic-linked .so from an APK.

typedef unsigned long size_t;
extern int __android_log_print(int prio, const char *tag, const char *fmt, ...);
extern int *__errno(void);
extern int __system_property_get(const char *name, char *value);
extern size_t strlen(const char *s);
extern void *malloc(size_t);
extern void free(void *);
extern void definitely_not_implemented(void);

#define LOGI(...) __android_log_print(4, "testlib", __VA_ARGS__)

// Pointers in data -> RELATIVE (or RELR / APS2 packed) relocations.
// Exported and non-const so the compiler can't fold the table away.
const char *words[] = { "hello", "from", "a", "bionic-style", ".so" };
// A bigger pointer table so lld actually emits packed (APS2) / RELR data.
static int slots[48];
#define P4(n) &slots[n], &slots[n + 1], &slots[n + 2], &slots[n + 3]
int *slot_ptrs[48] = { P4(0), P4(4), P4(8), P4(12), P4(16), P4(20),
                       P4(24), P4(28), P4(32), P4(36), P4(40), P4(44) };
static int ctor_ran;

__attribute__((constructor)) static void on_load(void) { ctor_ran = 1; }

int test_entry(const char *arg) {
    char sdk[92];
    LOGI("constructor ran: %d", ctor_ran);
    for (int i = 0; i < 5; i++) LOGI("words[%d] = %s", i, words[i]);
    for (int i = 0; i < 48; i++)
        if (slot_ptrs[i] != &slots[i]) { LOGI("relocation %d is wrong", i); return 2; }
    LOGI("48 data relocations verified");

    __system_property_get("ro.build.version.sdk", sdk);
    LOGI("ro.build.version.sdk = %s", sdk);

    *__errno() = 42;
    LOGI("errno roundtrip: %d", *__errno());

    char *p = malloc(64);
    LOGI("malloc from host libc: %s", p ? "ok" : "failed");
    free(p);

    LOGI("strlen(arg) = %d", (int)strlen(arg));
    if (arg[0] == '!') definitely_not_implemented(); // exercises the trap stub
    return ctor_ran && *__errno() == 42 ? 0 : 1;
}
