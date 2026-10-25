# OpenRoLauncher

An open-source (GPL-3.0-or-later) way to run the Android version of Roblox
natively on Linux, using the same approach as Sober: take the native
`libroblox.so` from the x86_64 APK and run it directly on Linux, replacing
the Android platform with our own implementations. No emulator, no container.

Short name: **ORL** — `orl-run` (runtime, C) and `orl` (launcher, Rust).

> Not affiliated with Roblox Corporation or with the Vinegar/Sober team.

## Status

| Stage | What | State |
|---|---|---|
| 1 | Extract native libs from an APK / split bundle | ✅ `tools/extract-apk.sh` |
| 2 | ELF loader + bionic shims | ✅ libc complete for libroblox |
| 3 | Fake JNI / JavaVM | ⏳ next |
| 4 | Window, Vulkan/EGL, audio, input (SDL2) | — |
| 5 | Launcher: stock mode, custom mode, multiple instances | — |
| 6 | Extra features (overlay, Discord RPC, asset mods...) | — |

### What the loader does

- maps `PT_LOAD` segments with correct protections, applies RELRO;
- handles every relocation format the Android NDK emits: plain RELA,
  `DT_RELR`, and Android packed relocations (APS2, `DT_ANDROID_RELA`);
- binds imports: our bionic shims first, then the host glibc, otherwise a
  trap stub that prints the symbol's name when called. Functions whose glibc
  ABI is known to differ are never bound to glibc (`BLOCKED`), so a mismatch
  fails loudly instead of corrupting memory;
- registers loaded libraries for `dl_iterate_phdr`/`dladdr`/`dlsym`, which
  C++ exception unwinding and backtraces depend on;
- `--imports` mode: lists every imported symbol and how it was resolved
  (shim / host / weak-null / MISSING / BLOCKED) without executing any code
  from the library. This is the map of what still needs to be written.

### Where bionic and glibc differ

These are bridged by shims (`src/shims_*.c`), checked by `tests/testabi.c`,
which is built for the real `x86_64-linux-android26` target:

| Area | Difference |
|---|---|
| stdio | old code names streams `&__sF[n]` (bionic `FILE` is 152 bytes) |
| signals | `sigset_t` is 8 bytes (glibc 128), `struct sigaction` field order |
| setjmp | `jmp_buf` is 88 bytes (glibc 200): own implementation |
| netdb | `addrinfo` swaps `ai_canonname`/`ai_addr`; `AI_`/`NI_`/`EAI_` values |
| sysconf | every `_SC_*` number is different |
| long double | IEEE quad on Android x86_64, x87 80-bit in glibc (math, `strtold`, `printf("%Lf")` varargs) |
| semaphores | `sem_t` is 16 bytes (glibc 32): own futex implementation |
| termios | kernel `struct termios` (36 bytes, glibc 60) |
| misc | `mallinfo` fields are `size_t`, `strerror_r` is POSIX, `__assert` argument order, static recursive mutex initializer, locale names, FORTIFY helpers |

## Building

Requires `gcc` or `clang` and `make`; the tests also need `clang` and `lld`.

```sh
make          # build/orl-run
make test     # one test library per relocation format + the bionic ABI test
```

## Trying it on the real client

```sh
tools/extract-apk.sh roblox.xapk          # .apk / .xapk / .apks
./build/orl-run -v --imports apk-libs/libroblox.so > imports.txt
```

You need the x86_64 build (in split bundles that's `config.x86_64.apk`).
Actually running the client's code isn't possible yet: it needs JNI (stage 3).

## Known limitations

- Everything not shimmed falls back to glibc. That's checked for every libc
  function libroblox imports, but a new client version may import more:
  check `BLOCKED` and new names in `--imports` after updating.
- `printf("%Lf")` narrows the quad to x87 (64-bit mantissa instead of 113),
  and positional `%1$Lf` isn't handled. `scanf("%Lf")` still stores an x87
  value where the caller expects a quad: the value is wrong, but the write
  stays inside the buffer. `PTHREAD_COND_INITIALIZER_MONOTONIC_NP` isn't
  translated.
- Static TLS relocations (`R_X86_64_TPOFF64` etc.) aren't supported yet;
  Android libraries usually use emutls, so this may never be needed.
- `DT_NEEDED` libraries aren't loaded: Android system libraries are replaced
  entirely by shims.

## Planned: multiple instances

Unlike Sober, ORL will let you run several Roblox windows at once. Each
window runs in its own **profile slot**: an isolated data directory
(`orl-run --data-dir <dir>`). Accounts inside a slot are managed by the
client's own account switcher; ORL never sees them.

- The default slot is `default`. "Another window" picks a free slot or
  creates a new one. Slots can be renamed (e.g. "main", "alt").
- A slot can't be opened twice at the same time, since both windows
  would share one session.
- The asset cache is shared between slots if the client handles concurrent
  writes, otherwise each slot gets its own.
- Input goes to the focused window. Discord RPC and the overlay work per
  window.

## Principles

- We run the official client as-is. Anti-cheat and integrity checks are not
  bypassed or modified.
- Features live around the client (launcher, overlay, window, input, assets),
  never inside game logic or process memory. No cheats.
- Login happens inside the client. Our code never handles passwords or cookies.

## License

GPL-3.0-or-later, see `LICENSE`.
