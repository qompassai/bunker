# /qompassai/bunker/crane.nix
# Qompass AI Bunker Crane.Nix Setup
# Copyright (C) 2025 Qompass AI, All rights reserved
####################################################
{ stdenv
, lib
, buildPackages
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
  cargoArtifacts = craneLib.buildDepsOnly ({
    pname = "bunker";
    inherit src version nativeBuildInputs buildInputs;
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
        installShellCompletion --cmd bunker \
          --bash <($out/bin/bunker gen-completions bash) \
          --zsh <($out/bin/bunker gen-completions zsh) \
          --fish <($out/bin/bunker gen-completions fish)
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
  inherit cargoArtifacts bunker bunker-client bunker-server bunker-tests;
}
