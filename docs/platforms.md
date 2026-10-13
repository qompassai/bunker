# Platform Clients: The Subset Build

The `bunker` client ships in two builds from one codebase. The **full
build** (the default) talks to a local Nix store through `libnixstore`
and offers every command. The **subset build** leaves the Nix store
support out and ships the commands that never needed it: managing
release artifacts, managing caches, and logging in — pure HTTP against
a Bunker server. The subset build is what runs on platforms with no
local Nix store, currently Windows and Android (through Termux).

The split is a Cargo feature. The client crate's `nix` feature is on by
default and pulls in the library's `nix_store` FFI bindings plus the
filesystem watcher. Building with `--no-default-features` produces the
subset client. Nothing about the server changes: it never linked the
client-side store bindings in the first place.

In a subset build the Nix commands do not disappear from the CLI.
`get-closure`, `push`, `use`, and `watch-store` stay listed and fail
with a clear error when invoked:

```text
Error: `bunker push` requires Nix store support, but this binary was
built without Nix store support (the `nix` feature is disabled).
Use a full build for Nix store commands.
```

<details>
<summary>The feature split</summary>

The library crate already gated its `libnixstore` C++ bridge behind
the `nix_store` feature; the client simply took the library with
default features, which turned the bridge on unconditionally. The
client now depends on the library with default features off
(`chunking`, `stream`, `tokio`) and re-enables `nix_store` only under
its own `nix` feature, together with the `notify`-based store watcher.

Under the feature, the Nix modules (`push`, `nix_config`, `nix_netrc`)
and the store-driving parts of `push`, `watch-store`, `get-closure`,
and `use` compile as before. Without it, each of those commands is a
stub that returns the error above. The Nix-only API methods on the
HTTP client (`upload_path`, `get_missing_paths`) are gated the same
way; everything the artifact, cache, and login commands use is shared.

Two portability fixes rode along. The configuration code used Unix-only
permission APIs unconditionally; file-mode handling is now `cfg(unix)`
(the file lives in a private per-user directory on other platforms).
And the `xdg` crate turns out to have no Windows support at all — its
`BaseDirectories` type does not exist there — so the configuration
directory is resolved per platform: XDG on Unix, `%APPDATA%\bunker` on
Windows. See `client/src/config.rs`.

</details>

<details>
<summary>Windows: the native subset client</summary>

Build (cross-compiled from Linux with the mingw-w64 toolchain):

```bash
cargo build -p bunker-client --no-default-features --release \
    --target x86_64-pc-windows-gnu
```

This produces a native PE32+ x86-64 console executable that imports
only standard Windows system DLLs (KERNEL32, ADVAPI32, WS2_32,
bcrypt, crypt32, the UCRT set). Configuration is stored in
`%APPDATA%\bunker\config.toml`, which is private to the user account.

What works: `artifact` (push, pull, rm), `cache`, and `login` — the
full artifact workflow against any reachable Bunker server. What does
not: the Nix commands, per the error above; there is no Nix store on
Windows for them to talk to. For the full client on a Windows machine,
use the WSL2 route below.

Verification status: the executable was run under Wine on Linux —
`--help` and `--version` exit cleanly, the Nix commands produce the
expected refusal, and a cache command loads configuration through the
`%APPDATA%` path. It has not yet been run on real Windows hardware.

</details>

<details>
<summary>Windows: the full client through WSL2</summary>

The full client is a Linux program, so on Windows it runs inside
WSL2:

1. Install WSL2 with a Linux distribution and install Nix inside it.
2. Clone this repository inside the WSL2 filesystem.
3. `nix develop`, then `cargo build` (default features), or build the
   flake's client package.

Configuration and credentials live in the WSL2 home directory
(`~/.config/bunker/config.toml`), separate from the native subset
client's `%APPDATA%` configuration.

One caveat that matters: `watch-store` relies on filesystem change
notifications. The `/mnt/c` drvfs mount does not deliver those events
reliably for files changed by Windows programs, and a Nix store on
drvfs fights its permission and locking semantics besides. Keep the
Nix store and anything `watch-store` watches on the WSL2 filesystem
(ext4) itself, not under `/mnt/c`.

</details>

<details>
<summary>Android: the subset client in Termux</summary>

Build with `cargo-ndk` against the Android NDK (built and verified
with NDK r30):

```bash
ANDROID_NDK_HOME=/path/to/ndk cargo ndk -t arm64-v8a build \
    -p bunker-client --no-default-features --release
```

Install in Termux: copy `target/aarch64-linux-android/release/bunker`
to the device, then in Termux:

```bash
chmod +x bunker
./bunker --help
mv bunker $PREFIX/bin/   # optional: put it on PATH
```

The binary is a 64-bit ARM PIE executable linked only against
Android's system libraries (`libc`, `libm`, `libdl` — the bionic C
library, through `/system/bin/linker64`). It needs no Termux packages
and no glibc; it is an Android binary, not a Linux/glibc one, and will
not run on a desktop Linux. The minimum Android version is API 21
(Android 5.0), and the target is arm64-v8a, which covers effectively
every device running a current Termux. Configuration lives at
`~/.config/bunker/config.toml` under the Termux home directory.

The command surface is the same subset as Windows: `artifact`,
`cache`, and `login` work; the Nix commands refuse with the error
above, as there is no Nix store in Termux either.

Verification status: the ELF was verified (architecture, interpreter,
dynamic dependencies). No Android device or emulator was attached
during the build session, so the first on-device check is still
`./bunker --help` after copying it over.

</details>

<details>
<summary>What the subset excludes, and why</summary>

| Command | Why it needs the full build |
| --- | --- |
| `get-closure` | Computes a path's closure by querying the local store. |
| `push` | Reads paths, NARs, and signatures from the local store through `libnixstore`. |
| `use` | Writes the local Nix configuration so Nix trusts and uses a cache. |
| `watch-store` | Watches the local store directory and pushes new paths as they appear. |

Every excluded command is excluded for the same reason: its input is
a *local* Nix store, and neither Windows nor Android/Termux has one.
The artifact workflow was designed store-free from the start — an
artifact is a file, a digest, and metadata — so it loses nothing in
the subset.

What was deliberately **not** built: a pure-Rust reimplementation of
the store-reading half (NAR writing, store database queries) that
could free the *full* client from `libnixstore` on Linux. That is a
much larger project, and it would buy Windows and Android nothing —
with no store on the device there is nothing for it to read. The
feature split gets the platforms their working client now and keeps
the full client's behavior on Linux byte-for-byte the same code paths
as before.

</details>

<details>
<summary>Build commands and verified artifacts</summary>

| Platform | Build command | Artifact |
| --- | --- | --- |
| Linux (subset) | `cargo build -p bunker-client --no-default-features --release` | `target/release/bunker` |
| Windows (subset) | `cargo build -p bunker-client --no-default-features --release --target x86_64-pc-windows-gnu` | `target/x86_64-pc-windows-gnu/release/bunker.exe` |
| Android (subset) | `cargo ndk -t arm64-v8a build -p bunker-client --no-default-features --release` | `target/aarch64-linux-android/release/bunker` |

Verified artifacts from the build session that introduced the split
(October 2026; rebuilds will differ in hash, as timestamps and build
paths are embedded):

- `bunker.exe` — 39,193,603 bytes, PE32+ x86-64,
  sha256 `9ed82dc0f07438468fff2136f99e19576348787e2ffcfe666a0de0c903ecc737`
- `bunker` (Android) — 41,021,888 bytes, ELF aarch64, Android API 21,
  sha256 `2e3c3c361eb8f67867817cb68f0cb763927424eb34b42df67fd612dbbb662de2`

</details>
