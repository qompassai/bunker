# /qompassai/bunker/crane.nix
# Qompass AI Bunker Crane.Nix Setup
# Copyright (C) 2025 Qompass AI, All rights reserved
####################################################
{ stdenv
, lib
, buildPackages
, cmake
, craneLib
, rust
, runCommand
, writeReferencesToFile
, pkg-config
, installShellFiles
, jq

, nix
, boost
, darwin
, libiconv
, openssl
, perl
, extraPackageArgs ? {}
}:
let
  version = "0.1.0";
  ignoredPaths = [
    ".ci"
    ".github"
    "book"
    "flake"
    "integration-tests"
    "nixos"
    "target"
  ];
  src = lib.cleanSourceWith {
    filter = name: type: !(type == "directory" && builtins.elem (baseNameOf name) ignoredPaths);
    src = lib.cleanSource ./.;
  };
  nativeBuildInputs = [
    pkg-config
    installShellFiles
    # The shared deps build compiles the whole workspace
    # dependency graph, so build tools needed by any member's
    # build scripts belong here: cmake for libz-ng-sys (drives
    # zlib-ng with cmake) and perl for openssl-sys (the vendored
    # OpenSSL build's Configure script needs it).
    cmake
    perl
  ];
  buildInputs = [
    nix boost
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.SystemConfiguration
    libiconv
  ];
  crossArgs = let
    rustTargetSpec = rust.toRustTargetSpec stdenv.hostPlatform;
    rustTargetSpecEnv = lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] rustTargetSpec);
  in lib.optionalAttrs (stdenv.hostPlatform != stdenv.buildPlatform) {
    depsBuildBuild = [ buildPackages.stdenv.cc ];
    CARGO_BUILD_TARGET = rustTargetSpec;
    "CARGO_TARGET_${rustTargetSpecEnv}_LINKER" = "${stdenv.cc.targetPrefix}cc";
  };
  extraArgs = crossArgs // extraPackageArgs;
  # Deliberately no --cfg tokio_unstable in the Nix builds. The
  # repo's .cargo/config.toml sets that flag for host builds,
  # which makes pingora-runtime call tokio's unstable alt-timer
  # API -- an API that only exists in tokio >= 1.49, while
  # Cargo.lock pins tokio 1.45.1. Nothing in this workspace
  # enables pingora's alt-timer option, so the stable path is
  # the same behavior. RUSTFLAGS is the one lever cargo treats
  # as a full replacement for config-file rustflags
  # (CARGO_BUILD_RUSTFLAGS is merely joined with them), so it
  # is set, to an inert marker cfg, on every derivation that
  # compiles the workspace dependency graph.
  sandboxRustflags = "--cfg bunker_nix_build";
  cargoArtifacts = craneLib.buildDepsOnly ({
    pname = "bunker";
    inherit src version nativeBuildInputs buildInputs;
    RUSTFLAGS = sandboxRustflags;
    installCargoArtifactsMode = "use-zstd";
  } // extraArgs);
  mkBunker = args: craneLib.buildPackage ({
    pname = "bunker";
    inherit src version nativeBuildInputs buildInputs cargoArtifacts;
    BUNKER_DISTRIBUTOR = "bunker";
    NIX_INCLUDE_PATH = "${lib.getDev nix}/include";
    doCheck = false;
    cargoExtraArgs = "-p bunker-client -p bunker-server";
    postInstall = lib.optionalString (stdenv.hostPlatform == stdenv.buildPlatform) ''
      if [[ -f $out/bin/bunker ]]; then
        # The binary links libnixstore and libstdc++, but its
        # rpath is only patched in fixup, after postInstall --
        # point the loader at those lib dirs for completion
        # generation.
        export LD_LIBRARY_PATH="${lib.makeLibraryPath [ nix stdenv.cc.cc.lib ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        installShellCompletion --cmd bunker \
          --bash <($out/bin/bunker gen-completions bash) \
          --zsh <($out/bin/bunker gen-completions zsh) \
          --fish <($out/bin/bunker gen-completions fish)
      fi
    '';
    # The client binary links the nix C++ libraries, but cargo
    # leaves its rpath empty and fixup only shrinks rpaths --
    # add the lib dirs it needs or the installed binary cannot
    # start.
    postFixup = ''
      if [[ -f $out/bin/bunker ]]; then
        patchelf --add-rpath "${lib.makeLibraryPath [ nix stdenv.cc.cc.lib ]}" $out/bin/bunker
      fi
    '';
    meta = with lib; {
      description = "Quality Nix cache system";
      homepage = "https://github.com/qompassai/bunker";
      license = licenses.asl20;
      maintainers = with maintainers; [ phaedrusflow ];
      platforms = platforms.linux ++ platforms.darwin;
      mainProgram = "bunker";
    };
    passthru = {
      inherit nix;
    };
  } // args // extraArgs);
  bunker = mkBunker {
    cargoExtraArgs = "-p bunker-client -p bunker-server";
  };
  bunker-client = mkBunker {
    cargoExtraArgs = " -p bunker-client";
  };
  bunker-proxy = craneLib.buildPackage ({
    pname = "bunker-proxy";
    inherit src version nativeBuildInputs;
    # The proxy links the system openssl package here, but its
    # dependency tree also builds OpenSSL from source (openssl-src
    # in Cargo.lock; the vendored OpenSSL carries the ML-KEM
    # hybrid groups) -- that is what the shared perl is for.
    buildInputs = buildInputs ++ [ openssl ];
    # See sandboxRustflags above: no tokio_unstable cfg in the
    # Nix build (the locked tokio predates the alt-timer API).
    RUSTFLAGS = sandboxRustflags;
    doCheck = false;
    cargoExtraArgs = "-p bunker-proxy";
    CARGO_PROFILE_RELEASE_LTO = "fat";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
    meta = {
      mainProgram = "bunker-proxy";
    };
  } // extraArgs);
  bunker-server = craneLib.buildPackage ({
    pname = "bunker-server";
    inherit src version nativeBuildInputs buildInputs;
    doCheck = false;
    cargoExtraArgs = "-p bunker-server";
    CARGO_PROFILE_RELEASE_LTO = "fat";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
    meta = {
      mainProgram = "bunkerd";
    };
  } // extraArgs);
  bunker-tests = craneLib.mkCargoDerivation ({
    pname = "bunker-tests";
    inherit src version buildInputs cargoArtifacts;
    nativeBuildInputs = nativeBuildInputs ++ [ jq ];
    doCheck = true;
    buildPhaseCargoCommand = "";
    checkPhaseCargoCommand = "cargoWithProfile test --no-run --message-format=json >cargo-test.json";
    doInstallCargoArtifacts = false;
    NIX_INCLUDE_PATH = "${lib.getDev nix}/include";
    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      jq -r 'select(.reason == "compiler-artifact" and .target.test and .executable) | .executable' <cargo-test.json | \
        xargs -I _ cp _ $out/bin
      runHook postInstall
    '';
  } // extraArgs);
in {
  inherit cargoArtifacts bunker bunker-client bunker-proxy bunker-server bunker-tests;
}
