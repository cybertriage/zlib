# zlib for Cyber Triage

This fork builds the zlib static library, `zlibstat.lib`, that the Cyber
Triage collector (`CyberTriageTool/CyberTriageCollector`) links, for 32-bit
Windows. The collector writes its collection as a gzip file and records the
file's SHA-256 and size in its manifest, which this fork's patch computes as
the file is written.

Work happens on `ct-1.3`, which is upstream's
[v1.3.2](https://github.com/madler/zlib/releases/tag/v1.3.2) tag plus the
commits below. `ct-1.3` drops upstream's own workflows, which run on every
push and build without Mbed TLS, which the patched `zlib.h` needs.

## What differs from upstream

- **SHA-256 of gzip output** (`zlib.h`, `gzclose.c`, `gzlib.c`, `gzwrite.c`).
  `gz_hash_init()` starts a SHA-256 of every byte written to the file from
  then on: the gzip stream, header and trailer included, or the raw data for a
  transparent (`"T"`) write. `gzclose_hash()` closes the file like
  `gzclose()`, and first stores the hash, or 32 zero bytes if hashing was not
  started or failed, and the file offset, which for a new file is its size.
  The collector calls `gzopen_w`, `gz_hash_init`, then `gzwrite` and
  `gzoffset`, then `gzclose_hash`, so the hash and size are those of the file
  on disk. The hashing uses Mbed TLS: `zlib.h` includes `mbedtls/sha256.h` and
  `z_stream` holds an `mbedtls_sha256_context`.
- **Release build.** `.github/workflows/ct_release.yml` and the files in
  `ct/` build and check the library.

The patch comes from APriestman/zlib's `addHashing` branch (12fcb17263),
written for zlib 1.3.1, and was rebased onto 1.3.2 with these changes:

- zlib 1.3.2 supports non-blocking files: a `write()` may write part of what
  it was given, or fail with `EAGAIN`, and zlib writes the rest later. The
  1.3.1 patch hashed each buffer before writing it, which would hash a retried
  remainder twice. The fork hashes what each `write()` actually wrote, after
  it succeeds, so the hash is still exactly that of the file.
- `gzclose_hash_w()` was a copy of `gzclose_w()`. Now `gzclose_w()` calls
  `gzclose_hash_w()` without outputs, so they cannot drift apart, and
  `gzclose()` frees an unfinished hash, as on the collector's error path.
- Either output of `gzclose_hash()` may be `NULL`.

## zlib 1.3.2 changes that matter to the collector

- **`z_off_t` is 64 bits.** zlib 1.3.1 on Windows made it a 32-bit `long`, so
  `gzoffset()` stopped working past 2 GB, and the collector refuses split
  sizes over 2 GB because of it (CT-9941). zlib 1.3.2 makes `z_off_t`
  `long long`. The collector's `(uint64_t)gzoffset(...)` compiles and works
  unchanged, and the 2 GB limit could be lifted. `gzseek`, `gztell`,
  `gzoffset`, `adler32_combine` and `crc32_combine` change type with it, so the
  collector must compile against the `zlib.h` and `zconf.h` from the same
  release as `zlibstat.lib`.
- **No Visual Studio projects.** zlib 1.3.2 removed `contrib/vstudio`, which
  built the old library. The fork builds with zlib's CMake build instead.
- The collector's other zlib calls, `deflateInit`/`deflate`/`deflateEnd`,
  `compress`, `adler32` and `crc32`, are unchanged; the probe exercises them.

## Mbed TLS

zlib compiles against the headers of a
[cybertriage/mbedtls](https://github.com/cybertriage/mbedtls) package, which
`ct/mbedtls.json` pins by SHA-256. The collector must link the `mbedTLS.lib`
from that same package: `z_stream` holds an `mbedtls_sha256_context`, so its
layout comes from those headers. Each release's `SOURCE.txt` names the Mbed
TLS package it was built against. `zlibstat.lib` contains no Mbed TLS code.

`ct/mbedtls.json` names either a release:

```json
{"repo": "cybertriage/mbedtls", "tag": "ct-20261017.1", "asset": "mbedtls-ct-20261017.1-win32.zip", "sha256": "..."}
```

or, until Mbed TLS has its first release, the package artifact of a
`ct_release` run, with `"run_id"` instead of `"tag"`. Workflow artifacts
expire, so switch to a release as soon as there is one: set `tag`, `asset` and
`sha256` from the release and its `SHA256SUMS`, drop `run_id`, and release
zlib again.

## The build

One library serves every collector configuration. It is built with the
v141_xp toolset, the oldest the collector uses, because a newer linker can
link older objects but not the reverse. The workflow installs the v141 build
tools and Windows XP support on the runner. The library is built with:

- `ZLIB_WINAPI`, the stdcall convention the collector compiles with;
- `/MT` code that names no C runtime (`/Zl`), so it links into `/MT`, `/MD`
  and `/MDd` executables without LNK4098, using the executable's C runtime;
- no `/GL`, because link-time code generation objects only link with the
  exact compiler that built them;
- `/Z7`, which keeps the debug information in the objects, so there is no
  PDB to ship and no LNK4099;
- no minizip, and no Mbed TLS folded in.

CMake names the library `zs.lib`; the package calls it `zlibstat.lib`, the
name the collector links. The package's `zconf.h` is the one CMake generated
for the build.

## The checks

`ct/ci.py check` fails the workflow unless every object is x86, none is a
`/GL` object, none refers to a PDB, all were compiled by the v141_xp compiler
(19.1x), none names a default library, the library defines the stdcall
functions the collector calls, and it defines no Mbed TLS function but leaves
the SHA-256 ones to the executable.

`ct/probe.c` is then built four times, as each collector configuration links
`zlibstat.lib`: v141_xp `/MT` (Release_XPNoLibs), v142 `/MT` (Release_NoLibs
and its variants), v142 `/MD` (Release, Release_UAC) and v142 `/MDd`
(Debug), each with the matching `mbedTLS.lib`, and links with warnings as
errors. Each run writes gzip files as the collector does, with large and
small writes, a transparent write and an empty file, checks the hash and size
`gzclose_hash` reports against the file, reads the file back, and exercises
the rest of the zlib API the collector uses. `ct/ci.py run-probe` then
recomputes each file's SHA-256 and size independently with Python's hashlib.

The package's `BUILD.txt` holds the check and probe reports.

## Getting the library

Do not build locally. Download a release from this repository's Releases
page. Each release has:

| File | Contents |
|---|---|
| `zlib-<tag>-win32.zip` | `zlibstat.lib`, `zlib.h`, `zconf.h`, `LICENSE`, `SOURCE.txt`, `BUILD.txt` |
| `SHA256SUMS` | SHA-256 of the archive |

`SOURCE.txt` names the exact source commit, build and Mbed TLS package. Every
push to `ct-1.3`, or to another `ct-*` branch, builds the same archive and
keeps it as a workflow artifact for the run. Only a tag publishes a release.

## Making a release

1. Make sure `ct/mbedtls.json` pins the Mbed TLS release the collector will
   link, and the `ct_release` workflow passes on `ct-1.3`.
2. Tag the commit `ct-<yyyymmdd>.<n>`, for example `ct-20261017.1`.
3. Push the tag. The workflow publishes the release.

Never move or reuse a tag. Cyber Triage pins a release by its SHA-256.

## Updating zlib

Merge the new upstream tag into `ct-1.3`, resolve the patch against it, and
update this README. Check the hashing still covers every `write()` in
`gzwrite.c`.

## Licence

The zlib licence, the same as upstream, in `LICENSE`. The source for every
release is this repository at the commit named in its `SOURCE.txt`.
