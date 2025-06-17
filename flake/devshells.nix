# Development shells

toplevel @ { lib, flake-parts-lib, ... }:
let
  inherit (lib)
    mkOption
    types
    ;
  inherit (flake-parts-lib)
    mkPerSystemOption
    ;
in
{
  options = {
    perSystem = mkPerSystemOption {
      options.bunker.devshell = {
        packageSets = mkOption {
          type = types.attrsOf (types.listOf types.package);
          default = {};
        };
        extraPackages = mkOption {
          type = types.listOf types.package;
          default = [];
        };
        extraArgs = mkOption {
          type = types.attrsOf types.unspecified;
          default = {};
        };
      };
    };
  };

  config = {
    perSystem = { self', pkgs, config, ... }: let
      cfg = config.bunker.devshell;
    in {
      bunker.devshell.packageSets = with pkgs; {
        rustc = lib.optionals (config.bunker.toolchain == null) [
          rustc
        ];
        rust = [
          cargo-expand
          cargo-outdated
          cargo-edit
          tokio-console
        ];
        linters = [
          clippy
          rustfmt
          editorconfig-checker
        ];
        utils = [
          jq
          just
        ];
        ops = [
          postgresql
          sqlite-interactive
          flyctl
          skopeo
          manifest-tool
        ] ++ lib.optionals pkgs.stdenv.isLinux [
          wrangler
        ];
        bench = [
          wrk
        ] ++ lib.optionals pkgs.stdenv.isLinux [
          linuxPackages.perf
        ];
        wasm = [
          llvmPackages_latest.bintools
          worker-build wasm-pack wasm-bindgen-cli
        ];
      };
      devShells.default = pkgs.mkShell (lib.recursiveUpdate {
        inputsFrom = [
          self'.packages.bunker
          self'.packages.book
        ];
        packages = lib.flatten (lib.attrValues cfg.packageSets);
        env = {
          BUNKER_DISTRIBUTOR = toplevel.config.bunker.distributor;
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustcSrc}/library";
          NIX_PATH = "nixpkgs=${pkgs.path}";
          NIX_INCLUDE_PATH = "${lib.getDev self'.packages.bunker.passthru.nix}/include";
          NIX_VERSIONS = config.bunker.nix-versions.manifestFile;
        };
      } cfg.extraArgs);

      devShells.demo = pkgs.mkShell {
        packages = [ self'.packages.default ];

        shellHook = ''
          >&2 echo
          >&2 echo '🚀 Run `bunkerd` to get started!'
          >&2 echo
        '';
      };
    };
  };
}
