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
| 2 | ELF loader + bionic shims | ✅ prototype |
| 3 | Fake JNI / JavaVM | ⏳ next |
| 4 | Window, Vulkan/EGL, audio, input (SDL2) | — |
| 5 | Launcher: stock mode and custom mode | — |
| 6 | Extra features (overlay, Discord RPC, asset mods...) | — |

### What the loader does

- maps `PT_LOAD` segments with correct protections, applies RELRO;
- handles every relocation format the Android NDK emits: plain RELA,
  `DT_RELR`, and Android packed relocations (APS2, `DT_ANDROID_RELA`);
- binds imports: our bionic shims first, then the host glibc, otherwise a
  trap stub that prints the symbol's name when called;
- `--imports` mode: lists every imported symbol and how it was resolved
  (shim / host / MISSING) without executing any code from the library.
  This is the map of what still needs to be written.

## Building

Requires `gcc` or `clang` and `make`; the tests also need `clang` and `lld`.

```sh
make          # build/orl-run
make test     # three test libraries, one per relocation format
```

## Trying it on the real client

```sh
tools/extract-apk.sh roblox.xapk          # .apk / .xapk / .apks
./build/orl-run -v --imports apk-libs/libroblox.so > imports.txt
```

You need the x86_64 build (in split bundles that's `config.x86_64.apk`).
Actually running the client's code isn't possible yet: it needs JNI (stage 3).

## Known limitations

- Falling back to glibc works for simple functions (`malloc`, `strlen`...),
  but bionic and glibc differ in some struct layouts (`FILE`, `struct stat`,
  `pthread_attr_t`, `sigaction`, `dirent`, locales). Those functions will be
  moved into shims as they show up in `--imports`.
- Static TLS relocations (`R_X86_64_TPOFF64` etc.) aren't supported yet;
  Android libraries usually use emutls, so this may never be needed.
- `DT_NEEDED` libraries aren't loaded: Android system libraries are replaced
  entirely by shims.

## Principles

- We run the official client as-is. Anti-cheat and integrity checks are not
  bypassed or modified.
- Features live around the client (launcher, overlay, window, input, assets),
  never inside game logic or process memory. No cheats.
- Login happens inside the client. Our code never handles passwords or cookies.

## License

GPL-3.0-or-later, see `LICENSE`.
