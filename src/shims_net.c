// SPDX-License-Identifier: GPL-3.0-or-later
// Name resolution. bionic's netdb.h comes from BSD, glibc's doesn't:
//   struct addrinfo swaps ai_canonname and ai_addr;
//   AI_*, NI_* and EAI_* have different values (EAI_* are positive in bionic).
// Sockets, sockaddr, msghdr and friends are kernel layouts in both libcs.

#define _GNU_SOURCE
#include "shims.h"

#include <netdb.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

struct b_addrinfo {
    int ai_flags, ai_family, ai_socktype, ai_protocol;
    socklen_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct b_addrinfo *ai_next;
};
_Static_assert(sizeof(struct b_addrinfo) == sizeof(struct addrinfo), "addrinfo size");
_Static_assert(offsetof(struct b_addrinfo, ai_next) == offsetof(struct addrinfo, ai_next),
               "addrinfo ai_next");

enum {
    B_AI_PASSIVE = 0x1, B_AI_CANONNAME = 0x2, B_AI_NUMERICHOST = 0x4, B_AI_NUMERICSERV = 0x8,
    B_AI_ALL = 0x100, B_AI_ADDRCONFIG = 0x400, B_AI_V4MAPPED = 0x800,
    // bionic rejects anything else with EAI_BADFLAGS
    B_AI_MASK = B_AI_PASSIVE | B_AI_CANONNAME | B_AI_NUMERICHOST | B_AI_NUMERICSERV |
                B_AI_ADDRCONFIG,
};
static const struct { int b, h; } ai_flags[] = {
    { B_AI_PASSIVE, AI_PASSIVE }, { B_AI_CANONNAME, AI_CANONNAME },
    { B_AI_NUMERICHOST, AI_NUMERICHOST }, { B_AI_NUMERICSERV, AI_NUMERICSERV },
    { B_AI_ALL, AI_ALL }, { B_AI_ADDRCONFIG, AI_ADDRCONFIG }, { B_AI_V4MAPPED, AI_V4MAPPED },
};

enum {
    B_NI_NOFQDN = 0x1, B_NI_NUMERICHOST = 0x2, B_NI_NAMEREQD = 0x4, B_NI_NUMERICSERV = 0x8,
    B_NI_DGRAM = 0x10,
};
static const struct { int b, h; } ni_flags[] = {
    { B_NI_NOFQDN, NI_NOFQDN }, { B_NI_NUMERICHOST, NI_NUMERICHOST },
    { B_NI_NAMEREQD, NI_NAMEREQD }, { B_NI_NUMERICSERV, NI_NUMERICSERV },
    { B_NI_DGRAM, NI_DGRAM },
};

enum { B_EAI_BADFLAGS = 3, B_EAI_FAIL = 4, B_EAI_BADHINTS = 12, B_EAI_PROTOCOL = 13 };
static const struct { int b, h; } eai_codes[] = {
    { 1, EAI_ADDRFAMILY }, { 2, EAI_AGAIN }, { 3, EAI_BADFLAGS }, { 4, EAI_FAIL },
    { 5, EAI_FAMILY }, { 6, EAI_MEMORY }, { 7, EAI_NODATA }, { 8, EAI_NONAME },
    { 9, EAI_SERVICE }, { 10, EAI_SOCKTYPE }, { 11, EAI_SYSTEM }, { 14, EAI_OVERFLOW },
};

#define MAP_BITS(tbl, from, to, v) ({                               \
    int out_ = 0;                                                   \
    for (size_t i_ = 0; i_ < sizeof tbl / sizeof tbl[0]; i_++)      \
        if ((v) & tbl[i_].from) out_ |= tbl[i_].to;                 \
    out_; })

static int eai_to_bionic(int h) {
    if (h == 0) return 0;
    for (size_t i = 0; i < sizeof eai_codes / sizeof eai_codes[0]; i++)
        if (eai_codes[i].h == h) return eai_codes[i].b;
    return B_EAI_FAIL;
}

// Convert one node in place between the two layouts. Done with memcpy at
// fixed offsets because the same bytes are viewed as two struct types.
#define AT(p, type, field) ((char *)(p) + offsetof(type, field))
static void swap_node(void *node, int to_bionic) {
    char *canon, *addr;
    int flags;
    if (to_bionic) {
        memcpy(&canon, AT(node, struct addrinfo, ai_canonname), sizeof canon);
        memcpy(&addr, AT(node, struct addrinfo, ai_addr), sizeof addr);
        memcpy(&flags, AT(node, struct addrinfo, ai_flags), sizeof flags);
        flags = MAP_BITS(ai_flags, h, b, flags);
        memcpy(AT(node, struct b_addrinfo, ai_canonname), &canon, sizeof canon);
        memcpy(AT(node, struct b_addrinfo, ai_addr), &addr, sizeof addr);
        memcpy(AT(node, struct b_addrinfo, ai_flags), &flags, sizeof flags);
    } else {
        memcpy(&canon, AT(node, struct b_addrinfo, ai_canonname), sizeof canon);
        memcpy(&addr, AT(node, struct b_addrinfo, ai_addr), sizeof addr);
        memcpy(&flags, AT(node, struct b_addrinfo, ai_flags), sizeof flags);
        flags = MAP_BITS(ai_flags, b, h, flags);
        memcpy(AT(node, struct addrinfo, ai_canonname), &canon, sizeof canon);
        memcpy(AT(node, struct addrinfo, ai_addr), &addr, sizeof addr);
        memcpy(AT(node, struct addrinfo, ai_flags), &flags, sizeof flags);
    }
}

static void *next_node(void *node) {
    void *next;
    memcpy(&next, AT(node, struct addrinfo, ai_next), sizeof next);
    return next;
}

// The list glibc returns is converted in place and converted back before
// glibc frees it, so every allocation stays glibc's.
static int b_getaddrinfo(const char *node, const char *service,
                         const struct b_addrinfo *hints, struct b_addrinfo **res) {
    struct addrinfo h, *list = NULL;
    if (hints) {
        if (hints->ai_flags & ~B_AI_MASK) return B_EAI_BADFLAGS;
        if (hints->ai_addrlen || hints->ai_canonname || hints->ai_addr || hints->ai_next)
            return B_EAI_BADHINTS;
        memset(&h, 0, sizeof h);
        h.ai_flags = MAP_BITS(ai_flags, b, h, hints->ai_flags);
        h.ai_family = hints->ai_family;
        h.ai_socktype = hints->ai_socktype;
        h.ai_protocol = hints->ai_protocol;
    }
    int r = getaddrinfo(node, service, hints ? &h : NULL, &list);
    if (r != 0) return eai_to_bionic(r);
    for (void *n = list; n; n = next_node(n)) swap_node(n, 1);
    *res = (struct b_addrinfo *)(void *)list;
    return 0;
}

static void b_freeaddrinfo(struct b_addrinfo *list) {
    for (void *n = list; n; n = next_node(n)) swap_node(n, 0);
    freeaddrinfo((struct addrinfo *)(void *)list);
}

static const char *b_gai_strerror(int code) {
    if (code == 0) return "Success";
    if (code == B_EAI_BADHINTS) return "Invalid value for hints";
    if (code == B_EAI_PROTOCOL) return "Resolved protocol is unknown";
    for (size_t i = 0; i < sizeof eai_codes / sizeof eai_codes[0]; i++)
        if (eai_codes[i].b == code) return gai_strerror(eai_codes[i].h);
    return "Unknown error";
}

// bionic declares the buffer lengths as size_t.
static int b_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen,
                         char *serv, size_t servlen, int flags) {
    int r = getnameinfo(sa, salen, host, (socklen_t)hostlen, serv, (socklen_t)servlen,
                        MAP_BITS(ni_flags, b, h, flags));
    return eai_to_bionic(r);
}

const shim_entry shims_net[] = {
    SHIM(getaddrinfo), SHIM(freeaddrinfo), SHIM(gai_strerror), SHIM(getnameinfo),
    { NULL, NULL }
};
