# 2026-10-13 — Platform subset clients (Windows / Android)

- The libnixstore coupling is fenced behind the client's `nix`
  feature. Subset builds (`--no-default-features`) are pure HTTP
  (artifact push/pull/rm, cache, login) and need no
  NIX_INCLUDE_PATH; the four Nix-only commands refuse with a
  clear "built without Nix store support" error.
- The `xdg` crate has NO Windows support at all. The client
  config path is per-platform: `%APPDATA%\bunker\config.toml`
  on Windows, XDG config dir on Unix.
- Cross-builds proven: `x86_64-pc-windows-gnu` subset binary
  (bunker.exe) smoke-tested under Wine — version, help, the
  no-Nix refusal, and config loading through the %APPDATA%
  path all pass. `aarch64-linux-android` built via cargo-ndk
  against NDK r30 (30.0.16248370): bionic-only NEEDED entries
  (libc/libm/libdl), API 21 floor; on-device execution smoke
  is still outstanding (no device attached).
- `docs/platforms.md` is the platform story of record: the
  feature split, the Windows subset, the WSL2 full-client
  route (watch-store over /mnt/c is the named weak spot), and
  the Android/Termux route.