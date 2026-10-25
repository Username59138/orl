// SPDX-License-Identifier: GPL-3.0-or-later
// Clearhead - minimal ELF loader for Android (bionic) x86_64 shared objects.
//
// What it does:
//   1. maps PT_LOAD segments of an ET_DYN ELF into one reserved region;
//   2. applies relocations: plain RELA, DT_RELR and Android's packed
//      relocations (APS2, DT_ANDROID_RELA);
//   3. binds imported symbols: our bionic shims first, then the host glibc,
//      otherwise a trap stub that names the missing symbol when called;
//   4. runs constructors on request and exposes exported symbols.
//
// What it deliberately does NOT do (yet): load DT_NEEDED dependencies
// (all Android system libs are replaced by shims), static TLS relocations.

#define _GNU_SOURCE
#include "loader.h"
#include "shims.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#define DT_RELR   36
#endif
#define DT_ANDROID_RELA     0x60000011
#define DT_ANDROID_RELASZ   0x60000012
#define DT_ANDROID_RELR     0x6fffe000
#define DT_ANDROID_RELRSZ   0x6fffe001
#ifndef R_X86_64_IRELATIVE
#define R_X86_64_IRELATIVE 37
#endif

#define LOG(...) fprintf(stderr, "[loader] " __VA_ARGS__)

struct so_module {
    char *path;
    int flags;
    uint8_t *map;        // start of reserved region
    size_t map_size;
    uintptr_t bias;      // runtime address = bias + p_vaddr
    Elf64_Phdr *phdr;
    int phnum;

    Elf64_Sym *symtab;
    const char *strtab;
    size_t nsyms;

    Elf64_Rela *rela;      size_t relasz;
    Elf64_Rela *jmprel;    size_t pltrelsz;
    uint64_t   *relr;      size_t relrsz;
    uint8_t    *aps2;      size_t aps2sz;

    void (*init)(void);
    void (**init_array)(void);
    size_t init_array_count;

    so_stats stats;
};

static size_t page_size(void) {
    static size_t ps;
    if (!ps) ps = (size_t)sysconf(_SC_PAGESIZE);
    return ps;
}
#define PAGE_DOWN(x) ((uintptr_t)(x) & ~(page_size() - 1))
#define PAGE_UP(x)   PAGE_DOWN((uintptr_t)(x) + page_size() - 1)

/* ---------------------------------------------------------------- traps --- */
// A missing import gets a tiny stub: mov rdi, <name>; mov rax, <handler>; jmp rax.
// Calling it prints which symbol the library wanted and aborts, which is far
// more useful than a segfault at address 0.

static uint8_t *trap_page;
static size_t trap_used, trap_cap;

static void trap_handler(const char *name) {
    fprintf(stderr, "\n[loader] FATAL: library called unimplemented symbol '%s'\n", name);
    abort();
}

static void *make_trap(const char *name) {
    enum { STUB = 32 };
    if (!trap_page || trap_used + STUB > trap_cap) {
        trap_cap = 64 * 1024;
        trap_page = mmap(NULL, trap_cap, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (trap_page == MAP_FAILED) { perror("mmap trap"); exit(1); }
        trap_used = 0;
    } else {
        mprotect(trap_page, trap_cap, PROT_READ | PROT_WRITE);
    }
    uint8_t *p = trap_page + trap_used;
    uint64_t n = (uint64_t)(uintptr_t)strdup(name);
    uint64_t h = (uint64_t)(uintptr_t)trap_handler;
    p[0] = 0x48; p[1] = 0xBF; memcpy(p + 2, &n, 8);   // mov rdi, imm64
    p[10] = 0x48; p[11] = 0xB8; memcpy(p + 12, &h, 8); // mov rax, imm64
    p[20] = 0xFF; p[21] = 0xE0;                        // jmp rax
    trap_used += STUB;
    mprotect(trap_page, trap_cap, PROT_READ | PROT_EXEC);
    return p;
}

/* -------------------------------------------------------------- symbols --- */

static size_t count_syms_gnu(const uint32_t *h) {
    uint32_t nbuckets = h[0], symoffset = h[1], bloom = h[2];
    const uint32_t *buckets = h + 4 + bloom * 2; // bloom words are 64-bit
    const uint32_t *chain = buckets + nbuckets;
    uint32_t last = 0;
    for (uint32_t i = 0; i < nbuckets; i++)
        if (buckets[i] > last) last = buckets[i];
    if (last < symoffset) return symoffset;
    while (!(chain[last - symoffset] & 1)) last++;
    return last + 1;
}

void *so_sym(so_module *m, const char *name) {
    for (size_t i = 1; i < m->nsyms; i++) {
        Elf64_Sym *s = &m->symtab[i];
        int bind = ELF64_ST_BIND(s->st_info);
        if (s->st_shndx == SHN_UNDEF) continue;
        if (bind != STB_GLOBAL && bind != STB_WEAK) continue;
        if (strcmp(m->strtab + s->st_name, name) == 0)
            return (void *)(m->bias + s->st_value);
    }
    return NULL;
}

// Resolve symbol index `idx` of the module for relocation purposes.
// Cache per index so each import is reported and trapped only once.
static uintptr_t *resolved_cache;

static uintptr_t resolve(so_module *m, uint32_t idx) {
    if (resolved_cache[idx]) return resolved_cache[idx];
    Elf64_Sym *s = &m->symtab[idx];
    const char *name = m->strtab + s->st_name;
    uintptr_t addr;
    const char *how;

    if (s->st_shndx != SHN_UNDEF) {
        addr = m->bias + s->st_value;
        how = NULL; // internal reference, not an import
    } else if ((addr = (uintptr_t)shim_lookup(name))) {
        how = "shim"; m->stats.shim++;
    } else if ((addr = (uintptr_t)dlsym(RTLD_DEFAULT, name))) {
        how = "host"; m->stats.host++;
    } else if (ELF64_ST_BIND(s->st_info) == STB_WEAK) {
        addr = 0; how = "weak-null"; m->stats.missing++;
    } else {
        addr = (uintptr_t)make_trap(name);
        how = "MISSING"; m->stats.missing++;
    }
    if (how && (m->flags & SO_REPORT))
        printf("%-9s %s\n", how, name);
    // weak-null resolves to 0; mark with 1 in cache? keep it simple: recompute
    resolved_cache[idx] = addr;
    return addr;
}

/* ---------------------------------------------------------- relocations --- */

static void apply_rela(so_module *m, const Elf64_Rela *r) {
    uintptr_t *where = (uintptr_t *)(m->bias + r->r_offset);
    uint32_t type = ELF64_R_TYPE(r->r_info);
    uint32_t sym = ELF64_R_SYM(r->r_info);

    switch (type) {
    case R_X86_64_NONE:
        break;
    case R_X86_64_RELATIVE:
        *where = m->bias + r->r_addend;
        break;
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT:
        *where = resolve(m, sym);
        break;
    case R_X86_64_64:
        *where = resolve(m, sym) + r->r_addend;
        break;
    case R_X86_64_IRELATIVE: {
        uintptr_t (*resolver)(void) = (void *)(m->bias + r->r_addend);
        *where = resolver();
        break;
    }
    default:
        if (m->flags & SO_VERBOSE)
            LOG("unsupported relocation type %u at 0x%lx\n", type,
                (unsigned long)r->r_offset);
        m->stats.unsupported_relocs++;
    }
}

static void apply_relr(so_module *m) {
    uintptr_t *where = NULL;
    size_t n = m->relrsz / sizeof(uint64_t);
    for (size_t i = 0; i < n; i++) {
        uint64_t e = m->relr[i];
        if ((e & 1) == 0) {
            where = (uintptr_t *)(m->bias + e);
            *where++ += m->bias;
        } else {
            uint64_t bits = e >> 1;
            for (int k = 0; bits; bits >>= 1, k++)
                if (bits & 1) where[k] += m->bias;
            where += 63;
        }
    }
}

// Android packed relocations ("APS2"): a stream of SLEB128 numbers.
static int64_t sleb(const uint8_t **p, const uint8_t *end) {
    int64_t v = 0; int shift = 0; uint8_t b;
    do {
        if (*p >= end) { LOG("APS2 stream truncated\n"); exit(1); }
        b = *(*p)++;
        v |= (int64_t)(b & 0x7f) << shift;
        shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40)) v |= -((int64_t)1 << shift);
    return v;
}

static void apply_aps2(so_module *m) {
    enum { BY_INFO = 1, BY_OFFSET_DELTA = 2, BY_ADDEND = 4, HAS_ADDEND = 8 };
    const uint8_t *p = m->aps2, *end = m->aps2 + m->aps2sz;
    if (m->aps2sz < 4 || memcmp(p, "APS2", 4) != 0) {
        LOG("bad packed relocation magic\n"); exit(1);
    }
    p += 4;
    int64_t count = sleb(&p, end);
    Elf64_Rela r = { .r_offset = (Elf64_Addr)sleb(&p, end) };
    int64_t done = 0;
    while (done < count) {
        int64_t gsize = sleb(&p, end);
        int64_t gflags = sleb(&p, end);
        int64_t gdelta = 0;
        if (gflags & BY_OFFSET_DELTA) gdelta = sleb(&p, end);
        if (gflags & BY_INFO) r.r_info = (Elf64_Xword)sleb(&p, end);
        if ((gflags & HAS_ADDEND) && (gflags & BY_ADDEND)) r.r_addend += sleb(&p, end);
        else if (!(gflags & HAS_ADDEND)) r.r_addend = 0;
        for (int64_t i = 0; i < gsize; i++) {
            r.r_offset += (gflags & BY_OFFSET_DELTA) ? gdelta : sleb(&p, end);
            if (!(gflags & BY_INFO)) r.r_info = (Elf64_Xword)sleb(&p, end);
            if ((gflags & HAS_ADDEND) && !(gflags & BY_ADDEND)) r.r_addend += sleb(&p, end);
            apply_rela(m, &r);
        }
        done += gsize;
    }
}

/* -------------------------------------------------------------- loading --- */

static int prot_of(uint32_t pf) {
    return ((pf & PF_R) ? PROT_READ : 0) | ((pf & PF_W) ? PROT_WRITE : 0) |
           ((pf & PF_X) ? PROT_EXEC : 0);
}

so_module *so_load(const char *path, int flags) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror(path); return NULL; }

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != sizeof eh ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG("%s: not an ELF file\n", path); close(fd); return NULL;
    }
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_X86_64) {
        LOG("%s: need an x86_64 library (take it from the x86_64 APK split)\n", path);
        close(fd); return NULL;
    }
    if (eh.e_type != ET_DYN) {
        LOG("%s: not a shared object\n", path); close(fd); return NULL;
    }

    so_module *m = calloc(1, sizeof *m);
    m->path = strdup(path);
    m->flags = flags;
    m->phnum = eh.e_phnum;
    m->phdr = calloc(eh.e_phnum, sizeof(Elf64_Phdr));
    ssize_t want = (ssize_t)(eh.e_phnum * sizeof(Elf64_Phdr));
    if (pread(fd, m->phdr, want, eh.e_phoff) != want) {
        LOG("%s: truncated program headers\n", path); close(fd); return NULL;
    }

    // 1. Reserve one contiguous region for all PT_LOAD segments.
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < m->phnum; i++) {
        Elf64_Phdr *ph = &m->phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        if (PAGE_DOWN(ph->p_vaddr) < lo) lo = PAGE_DOWN(ph->p_vaddr);
        if (PAGE_UP(ph->p_vaddr + ph->p_memsz) > hi) hi = PAGE_UP(ph->p_vaddr + ph->p_memsz);
    }
    m->map_size = hi - lo;
    m->map = mmap(NULL, m->map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m->map == MAP_FAILED) { perror("mmap reserve"); exit(1); }
    m->bias = (uintptr_t)m->map - lo;
    if (flags & SO_VERBOSE)
        LOG("%s mapped at %p (%zu KiB)\n", path, (void *)m->map, m->map_size / 1024);

    // 2. Map segments writable for now; final protections are set after relocation.
    for (int i = 0; i < m->phnum; i++) {
        Elf64_Phdr *ph = &m->phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t seg = m->bias + ph->p_vaddr;
        uintptr_t page = PAGE_DOWN(seg);
        uintptr_t file_end = seg + ph->p_filesz;
        uintptr_t mem_end = seg + ph->p_memsz;

        if (ph->p_filesz) {
            off_t off = (off_t)PAGE_DOWN(ph->p_offset);
            size_t len = ph->p_offset + ph->p_filesz - (uintptr_t)off;
            if (mmap((void *)page, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED, fd, off) == MAP_FAILED) {
                perror("mmap segment"); exit(1);
            }
            // zero the rest of the last file-backed page (start of .bss)
            if (mem_end > file_end)
                memset((void *)file_end, 0, PAGE_UP(file_end) - file_end);
        }
        uintptr_t anon = ph->p_filesz ? PAGE_UP(file_end) : page;
        if (PAGE_UP(mem_end) > anon) {
            if (mmap((void *)anon, PAGE_UP(mem_end) - anon, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                perror("mmap bss"); exit(1);
            }
        }
    }
    close(fd);

    // 3. Parse the dynamic section.
    Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < m->phnum; i++)
        if (m->phdr[i].p_type == PT_DYNAMIC)
            dyn = (Elf64_Dyn *)(m->bias + m->phdr[i].p_vaddr);
    if (!dyn) { LOG("%s: no PT_DYNAMIC\n", path); exit(1); }

    const uint32_t *sysv_hash = NULL, *gnu_hash = NULL;
    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        uintptr_t ptr = m->bias + d->d_un.d_ptr;
        switch (d->d_tag) {
        case DT_SYMTAB:        m->symtab = (Elf64_Sym *)ptr; break;
        case DT_STRTAB:        m->strtab = (const char *)ptr; break;
        case DT_HASH:          sysv_hash = (const uint32_t *)ptr; break;
        case DT_GNU_HASH:      gnu_hash = (const uint32_t *)ptr; break;
        case DT_RELA:          m->rela = (Elf64_Rela *)ptr; break;
        case DT_RELASZ:        m->relasz = d->d_un.d_val; break;
        case DT_JMPREL:        m->jmprel = (Elf64_Rela *)ptr; break;
        case DT_PLTRELSZ:      m->pltrelsz = d->d_un.d_val; break;
        case DT_RELR:
        case DT_ANDROID_RELR:  m->relr = (uint64_t *)ptr; break;
        case DT_RELRSZ:
        case DT_ANDROID_RELRSZ: m->relrsz = d->d_un.d_val; break;
        case DT_ANDROID_RELA:  m->aps2 = (uint8_t *)ptr; break;
        case DT_ANDROID_RELASZ: m->aps2sz = d->d_un.d_val; break;
        case DT_INIT:          m->init = (void (*)(void))ptr; break;
        case DT_INIT_ARRAY:    m->init_array = (void (**)(void))ptr; break;
        case DT_INIT_ARRAYSZ:  m->init_array_count = d->d_un.d_val / sizeof(void *); break;
        }
    }
    if (gnu_hash) m->nsyms = count_syms_gnu(gnu_hash);
    else if (sysv_hash) m->nsyms = sysv_hash[1];

    if (flags & SO_VERBOSE) {
        for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++)
            if (d->d_tag == DT_NEEDED)
                LOG("  needs %s (provided by shims/host)\n", m->strtab + d->d_un.d_val);
        LOG("  %zu symbols, rela=%zu plt=%zu relr=%zu packed=%zu bytes\n", m->nsyms,
            m->relasz / sizeof(Elf64_Rela), m->pltrelsz / sizeof(Elf64_Rela),
            m->relrsz / 8, m->aps2sz);
    }

    // 4. Relocate and bind imports.
    resolved_cache = calloc(m->nsyms ? m->nsyms : 1, sizeof(uintptr_t));
    if (m->relr) apply_relr(m);
    if (m->aps2) apply_aps2(m);
    for (size_t i = 0; i < m->relasz / sizeof(Elf64_Rela); i++) apply_rela(m, &m->rela[i]);
    for (size_t i = 0; i < m->pltrelsz / sizeof(Elf64_Rela); i++) apply_rela(m, &m->jmprel[i]);
    free(resolved_cache);
    resolved_cache = NULL;

    // 5. Final page protections, then RELRO read-only.
    for (int i = 0; i < m->phnum; i++) {
        Elf64_Phdr *ph = &m->phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t seg = m->bias + ph->p_vaddr;
        mprotect((void *)PAGE_DOWN(seg), PAGE_UP(seg + ph->p_memsz) - PAGE_DOWN(seg),
                 prot_of(ph->p_flags));
    }
    for (int i = 0; i < m->phnum; i++) {
        Elf64_Phdr *ph = &m->phdr[i];
        if (ph->p_type != PT_GNU_RELRO) continue;
        uintptr_t seg = m->bias + ph->p_vaddr;
        mprotect((void *)PAGE_DOWN(seg), PAGE_DOWN(seg + ph->p_memsz) - PAGE_DOWN(seg),
                 PROT_READ);
    }
    return m;
}

void so_run_init(so_module *m) {
    if (m->init) m->init();
    for (size_t i = 0; i < m->init_array_count; i++) {
        void (*f)(void) = m->init_array[i];
        // (void*)-1 and 0 are legal "skip" markers
        if (f && f != (void (*)(void))-1) f();
    }
}

so_stats so_get_stats(so_module *m) { return m->stats; }
