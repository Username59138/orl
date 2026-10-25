#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Estimate the JNI surface of the client: which Java methods and fields the
# native code can reach, which framework classes we have to fake, and which
# native methods Java calls through RegisterNatives instead of Java_* exports.
#
#   tools/jni-surface.py apk-libs/libroblox.so path/to/base.apk [outdir]
#
# A Java method counts as a callback candidate when its class is named in the
# binary and its name and JNI signature both appear as strings. Names of 1-2
# characters are R8-obfuscated and match by accident, so they're dropped, and
# so are the duplicates in Djinni's CppProxy classes. Rerun after every client
# update. Python stdlib only.

import collections
import os
import re
import struct
import sys
import zipfile

ACC_STATIC, ACC_NATIVE = 0x8, 0x100

CLASS_RE = re.compile(r'^\[*L?((?:java|javax|android|androidx|com|org|dalvik|kotlin)/[A-Za-z0-9_/$]+);?$')
TYPE = r'\[*(?:[ZBCSIJFDV]|L[A-Za-z0-9_/$]+;)'
SIG_RE = re.compile(r'^\((?:' + TYPE + r')*\)' + TYPE + '$')


# ------------------------------------------------------------------- ELF ---

def elf_strings_and_exports(path):
    data = open(path, 'rb').read()
    strings = set(s.decode() for s in re.findall(rb'[\x20-\x7e]+', data))
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', data, 0x3A)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    exports = set()
    for _, sh_type, _, _, off, size, link, _, _, entsize in sections:
        if sh_type != 11:  # SHT_DYNSYM
            continue
        stroff = sections[link][4]
        for k in range(size // entsize):
            name, _, _, shndx, _, _ = struct.unpack_from('<IBBHQQ', data, off + k * entsize)
            if shndx:  # defined
                end = data.index(b'\0', stroff + name)
                exports.add(data[stroff + name:end].decode())
    return strings, exports


# ------------------------------------------------------------------- DEX ---

def uleb(buf, off):
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, off


def read_dex(d):
    if d[:4] != b'dex\n':
        raise ValueError('not a dex file')
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    (str_n, str_off, type_n, type_off, proto_n, proto_off, field_n, field_off,
     meth_n, meth_off, cls_n, cls_off) = struct.unpack_from('<12I', d, 56)

    def string(i):
        _, off = uleb(d, u32(str_off + 4 * i))
        return d[off:d.index(b'\0', off)].decode('utf-8', 'replace')

    strings = [string(i) for i in range(str_n)]
    types = [strings[u32(type_off + 4 * i)] for i in range(type_n)]

    def type_list(off):
        if not off:
            return []
        return [types[struct.unpack_from('<H', d, off + 4 + 2 * k)[0]] for k in range(u32(off))]

    protos = []
    for i in range(proto_n):
        _, ret, params = struct.unpack_from('<3I', d, proto_off + 12 * i)
        protos.append('(' + ''.join(type_list(params)) + ')' + types[ret])
    fields = [struct.unpack_from('<HHI', d, field_off + 8 * i) for i in range(field_n)]
    methods = [struct.unpack_from('<HHI', d, meth_off + 8 * i) for i in range(meth_n)]

    classes = {}
    for i in range(cls_n):
        cidx, _, _, _, _, _, data_off, _ = struct.unpack_from('<8I', d, cls_off + 32 * i)
        cls = {'methods': [], 'fields': []}
        if data_off:
            off = data_off
            sizes = []
            for _ in range(4):
                v, off = uleb(d, off)
                sizes.append(v)
            for count in sizes[:2]:
                idx = 0
                for _ in range(count):
                    diff, off = uleb(d, off)
                    acc, off = uleb(d, off)
                    idx += diff
                    _, t, n = fields[idx]
                    cls['fields'].append((strings[n], types[t], acc))
            for count in sizes[2:]:
                idx = 0
                for _ in range(count):
                    diff, off = uleb(d, off)
                    acc, off = uleb(d, off)
                    _, off = uleb(d, off)  # code_off
                    idx += diff
                    _, p, n = methods[idx]
                    cls['methods'].append((strings[n], protos[p], acc))
        classes[types[cidx][1:-1]] = cls
    return classes


def read_apk(path):
    classes = {}
    with zipfile.ZipFile(path) as z:
        for name in sorted(n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex', n)):
            classes.update(read_dex(z.read(name)))
    return classes


def jni_mangle(cls, name):
    def m(s):
        out = []
        for ch in s:
            if ch == '/':
                out.append('_')
            elif ch in '_;[':
                out.append({'_': '_1', ';': '_2', '[': '_3'}[ch])
            elif ch.isascii() and ch.isalnum():
                out.append(ch)
            else:
                out.append('_0%04x' % ord(ch))
        return ''.join(out)
    return 'Java_' + m(cls) + '_' + m(name)


# ------------------------------------------------------------------ main ---

def main():
    if len(sys.argv) not in (3, 4):
        sys.exit('usage: tools/jni-surface.py libroblox.so base.apk [outdir]')
    lib, apk = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) == 4 else 'apk-libs/jni'

    strings, exports = elf_strings_and_exports(lib)
    dex = read_apk(apk)
    ref_classes = {m.group(1) for s in strings if (m := CLASS_RE.match(s))}
    sigs = {s for s in strings if SIG_RE.match(s)}

    real_name = lambda n: len(n) > 2 or n.startswith('<')
    callbacks, fields, used_sigs = [], [], set()
    in_dex = sorted(c for c in ref_classes if c in dex)
    framework = sorted(c for c in ref_classes if c not in dex)
    for c in in_dex:
        proxy = c.endswith('$CppProxy')
        for name, sig, acc in dex[c]['methods']:
            if name in strings and sig in sigs and not acc & ACC_NATIVE and real_name(name):
                used_sigs.add(sig)
                if not proxy or name == '<init>':
                    callbacks.append((c, name, sig, acc))
        for name, ftype, acc in dex[c]['fields']:
            if name in strings and real_name(name):
                fields.append((c, name, ftype, acc))

    natives = [(c, n, s) for c, cls in dex.items() for n, s, acc in cls['methods'] if acc & ACC_NATIVE]
    exported = [x for x in natives if jni_mangle(x[0], x[1]) in exports]
    registered = [x for x in natives if jni_mangle(x[0], x[1]) not in exports
                  and x[0].startswith(('com/roblox', 'org/fmod', 'com/google/androidgamesdk'))]

    os.makedirs(out, exist_ok=True)
    static = lambda acc: 'static ' if acc & ACC_STATIC else ''
    write = lambda name, lines: open(os.path.join(out, name), 'w').write(''.join(l + '\n' for l in lines))
    write('callbacks.txt', (f'{static(a)}{c}.{n}{s}' for c, n, s, a in callbacks))
    write('fields.txt', (f'{static(a)}{c}.{n} {t}' for c, n, t, a in fields))
    write('framework.txt', framework)
    write('natives_registered.txt', (f'{c}.{n}{s}' for c, n, s in registered))
    write('sigs_framework.txt', sorted(sigs - used_sigs))

    pkg = lambda c: '/'.join(c.split('/')[:3])
    print(f'classes named in the binary: {len(ref_classes)} '
          f'({len(in_dex)} in app DEX, {len(framework)} framework)')
    print(f'native -> Java: {len(callbacks)} methods in {len(set(c for c, *_ in callbacks))} classes, '
          f'{len(fields)} fields')
    for p, n in collections.Counter(pkg(c) for c, *_ in callbacks).most_common():
        print(f'    {n:4} {p}')
    print(f'Java -> native: {len(natives)} natives in DEX, {len(exported)} exported as Java_*, '
          f'{len(registered)} roblox/fmod/gamesdk ones via RegisterNatives')
    print(f'framework signatures: {len(sigs - used_sigs)} of {len(sigs)}')
    print(f'reports in {out}/')


main()
