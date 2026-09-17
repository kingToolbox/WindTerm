# Building on macOS (Apple Silicon)

## What this builds, and what it does not

This repository is a **partial** open source release of WindTerm. It contains
the reusable libraries; it does not contain the application. There is no
`main()`, no terminal widget, no session handling, and before this change there
was no build system at all.

So there is no way to produce a native `WindTerm.app` from this tree. What the
build produces is an **SDK**: the open source libraries, built natively for
Apple Silicon, plus their headers and a CMake package.

| Target | Library | Depends on |
|---|---|---|
| `WindTerm::onigmo` | `libonigmo.a` | - |
| `WindTerm::protocols` | `libwindterm-protocols.a` | Qt Core |
| `WindTerm::pty` | `libwindterm-pty.a` | Qt Core |
| `WindTerm::utility` | `libwindterm-utility.a` | Qt Core, Qt Network (Qt 6), Boost.Thread, OpenSSL |
| `WindTerm::widgets` | `libwindterm-widgets.a` | Qt Widgets |
| (bundled) | `libssh.a` | OpenSSL, zlib |

The upstream project publishes a macOS binary for `x86_64` only, which runs
under Rosetta 2 on Apple Silicon. Nothing in this repository changes that,
because the application is not here to rebuild.

## Requirements

```bash
brew install cmake qt openssl@3 boost
```

Xcode command line tools provide `pkgbuild` and `productbuild`.

Qt 6.2 or later is used by default; Qt 5.15 still works.

## Build

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH=/opt/homebrew -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
cmake --install build --prefix /usr/local/windterm
```

`CMAKE_OSX_ARCHITECTURES` defaults to `arm64` and the deployment target to
`12.0`. Both are set before `project()` so the compiler checks run against the
target ABI rather than the host.

### Universal binaries

```bash
cmake -S . -B build -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
```

This only links if every dependency is universal too. Homebrew's Qt, OpenSSL
and Boost are single-architecture, so a universal build needs Qt from the
official Qt installer (which ships universal macOS binaries) or
`-DWINDTERM_WITH_QT=OFF`.

## Options

| Option | Default | Effect |
|---|---|---|
| `WINDTERM_BUILD_SHARED` | `OFF` | Build shared libraries instead of static |
| `WINDTERM_WITH_LIBSSH` | `ON` | Build the bundled libssh |
| `WINDTERM_WITH_ONIGMO` | `ON` | Build the bundled Onigmo |
| `WINDTERM_WITH_QT` | `ON` | Build the Qt based libraries |
| `WINDTERM_WITH_UTILITY` | `ON` | Build Utility (needs OpenSSL and Boost) |
| `WINDTERM_WITH_WIDGETS` | `ON` | Build the Qt Widgets library |
| `WINDTERM_LIBSSH_GSSAPI` | `OFF` on macOS | libssh GSSAPI support |
| `ONIGMO_UNALIGNED_WORD_ACCESS` | `OFF` | Onigmo's unaligned fast path on arm64 |

## Installer

```bash
CMAKE_PREFIX_PATH=/opt/homebrew ./scripts/build-pkg.sh --arch arm64
```

Writes `dist/WindTerm-SDK-<version>-macOS-arm64.pkg`, installing into
`/usr/local/windterm`. The script verifies with `lipo` that every staged
library really contains the requested architectures and fails the build if one
does not.

The package is unsigned. To sign it, set a Developer ID Installer identity:

```bash
PKG_SIGN_IDENTITY="Developer ID Installer: Your Name (TEAMID)" ./scripts/build-pkg.sh
```

`pkgbuild` prints `write: Permission denied` and stores `._` AppleDouble
entries in the payload. That is expected: macOS stamps every file with a
`com.apple.provenance` extended attribute that cannot be removed, and
AppleDouble is how extended attributes travel inside a `.pkg`. The installer
merges them back onto the real files; no `._` file is ever written to disk.

## Using the SDK

```cmake
find_package(WindTerm REQUIRED)
target_link_libraries(myapp PRIVATE WindTerm::pty WindTerm::onigmo)
```

## CI

`.gitlab-ci.yml` builds on a macOS arm64 runner and uploads the `.pkg` to the
project's generic package registry as `windterm-sdk/<version>`, on tags and on
the default branch. The runner needs `cmake`, `qt`, `openssl@3` and `boost`
from Homebrew plus the Xcode command line tools; the pipeline checks for them
and fails with the exact `brew install` line if one is missing.

Adjust the `tags:` in `.macos_arm64` to match the runner registered on the
instance.

## Portability changes made for this

The open source subset did not compile as published. These are the fixes:

- `Pty.h` included `"Public/Spin.h"`, a directory that does not exist in this
  repository; the header is in `src/Utility`.
- `Pty::setErrorCode()` is declared cross-platform but its body called
  `FormatMessage()` with no guard, so it only ever compiled on Windows. On Unix
  it now formats the errno value.
- `UnixPty` did not match `Pty`'s interface: it declared `createProcess()` with
  `QProcessEnvironment`/`int` and `resizeWindow()` with `int`, both marked
  `final`, against a base class using `QStringList`/`qint16`. It also called a
  `Pty(QObject *)` constructor that does not exist.
- `ShellProcess::setupChildProcess()` is a Qt 5 hook removed in Qt 6. It is now
  `setChildProcessModifier()` on Qt 6, with the Qt 5 path kept.
- The child setup ran `utmpx` registration between `fork()` and `exec()`, where
  `pututxline()` is not async-signal-safe. It moved to the parent.
- `strncpy(utmpxInfo.ut_user, qgetenv("USER"), ...)` passed a `QByteArray`
  where a `const char *` was expected, and the `ut_line` value was read from a
  pointer into an already-destroyed temporary.
- `ut_id` was filled from `d + strlen(d) - sizeof(ut_id)`, which walks off the
  front of the buffer for short tty names.
- `UnixPty::stop()` dereferenced a null notifier when the process never
  started, and closed the master fd while the notifier still watched it.
- `UnixPty::write()` asserted that a single `write()` consumed the whole
  buffer, which is not true for a non-blocking master.
- `m_shellReadBuffer` was written from the notifier and read by `readAll()`
  with no locking, although the base class already carries a mutex.
- `UnixPty::moveToThread()` hid `QObject::moveToThread()`; it is now
  `moveProcessToThread()`.
- `PopupWidget` used `QApplication::desktop()` (removed in Qt 6) and
  `qFadeEffect()` from `private/qeffects_p.h`. They are now `QWidget::screen()`
  and a `QPropertyAnimation` on `windowOpacity`.
- `Cryptographic.cpp` included `<qpassworddigestor.h>`; `QPasswordDigestor`
  moved from QtCore to QtNetwork in Qt 6.
- The bundled libssh 0.9.5 defines `bool is_ssh_initialized()` without a
  prototype while building with `-Werror=strict-prototypes`, which current
  clang rejects. Its own header already declared `(void)`.

None of the WindTerm code contained x86 intrinsics, so nothing had to be
rewritten for AArch64 itself.

### Note on the bundled libssh

It is version 0.9.5, released in 2020. It is built here as-is. If these
libraries are going to be used for anything that faces a network, the vendored
copy is worth updating first.
