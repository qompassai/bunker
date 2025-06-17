{ self
, lib
, flake-parts-lib
, inputs
, config
, makeCranePkgs
, getSystem
, ...
}:

let
  inherit (lib)
    mkOption
    types
    ;
  inherit (flake-parts-lib)
    mkPerSystemOption
    ;

  # Re-evaluate perSystem with cross nixpkgs
  # HACK before https://github.com/hercules-ci/flake-parts/issues/95 is solved
  evalCross = { system, pkgs }: config.allSystems.${system}.debug.extendModules {
    modules = [
      ({ config, lib, ... }: {
        _module.args.pkgs = pkgs;
        _module.args.self' = lib.mkForce config;
      })
    ];
  };
in
{
  options = {
    perSystem = mkPerSystemOption {
      options.bunker = {
        toolchain = mkOption {
          type = types.nullOr types.package;
          default = null;
        };
        extraPackageArgs = mkOption {
          type = types.attrsOf types.anything;
          default = {};
        };
      };
    };
  };

  config = {
    _module.args.makeCranePkgs = lib.mkDefault (pkgs: let
      perSystemConfig = getSystem pkgs.system;
      craneLib = builtins.foldl' (acc: f: f acc) pkgs [
        inputs.crane.mkLib
        (craneLib:
          if perSystemConfig.bunker.toolchain == null then craneLib
          else craneLib.overrideToolchain config.bunker.toolchain
        )
      ];
    in pkgs.callPackage ../crane.nix {
      inherit craneLib;
      inherit (perSystemConfig.bunker) extraPackageArgs;
    });

    perSystem = { self', pkgs, config, cranePkgs, ... }: (lib.mkMerge [
      {
        _module.args.cranePkgs = makeCranePkgs pkgs;

        packages = {
          default = self'.packages.bunker;

          inherit (cranePkgs)
            bunker
            bunker-client
            bunker-server
          ;

          bunker-nixpkgs = pkgs.callPackage ../package.nix { };

          bunker-ci-installer = pkgs.callPackage ../ci-installer.nix {
            inherit self;
          };

          book = pkgs.callPackage ../book {
            bunker = self'.packages.bunker;
          };
        };
      }

      (lib.mkIf pkgs.stdenv.isLinux {
        packages = {
          bunker-server-image = pkgs.dockerTools.buildImage {
            name = "bunker-server";
            tag = "main";
            copyToRoot = [
              self'.packages.bunker-server

              # Debugging utilities for `fly ssh console`
              pkgs.busybox

              # Now required by the fly.io sshd
              pkgs.dockerTools.fakeNss
            ];
            config = {
              Entrypoint = [ "${self'.packages.bunker-server}/bin/bunkerd" ];
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
        };
      })

      (lib.mkIf (pkgs.system == "x86_64-linux") {
        packages = {
          bunker-server-image-aarch64 = let
            eval = evalCross {
              system = "aarch64-linux";
              pkgs = pkgs.pkgsCross.aarch64-multiplatform;
            };

          in eval.config.packages.bunker-server-image;
        };
      })

      # Unfortunately, x86_64-darwin fails to evaluate static builds
      (lib.mkIf (pkgs.system != "x86_64-darwin") {
        packages = {
          # TODO: Make this work with Crane
          bunker-static = (pkgs.pkgsStatic.callPackage ../package.nix {
            nix = pkgs.pkgsStatic.nixVersions.nix_2_18.overrideAttrs (old: {
              patches = (old.patches or []) ++ [
                # Diff: https://github.com/zhaofengli/nix/compare/501a805fcd4a90e2bc112e9547417cfc4e04ca66...1dbe9899a8acb695f5f08197f1ff51c14bcc7f42
                (pkgs.fetchpatch {
                  url = "https://github.com/zhaofengli/nix/compare/501a805fcd4a90e2bc112e9547417cfc4e04ca66...1dbe9899a8acb695f5f08197f1ff51c14bcc7f42.diff";
                  hash = "sha256-bxBZDUUNTBUz6F4pwxx1ZnPcOKG3EhV+kDBt8BrFh6k=";
                })
              ];
            });
          }).overrideAttrs (old: {
            nativeBuildInputs = (old.nativeBuildInputs or []) ++ [
              pkgs.nukeReferences
            ];

            # Read by pkg_config crate (do some autodetection in build.rs?)
            PKG_CONFIG_ALL_STATIC = "1";

            "NIX_CFLAGS_LINK_${pkgs.pkgsStatic.stdenv.cc.suffixSalt}" = "-lc";
            RUSTFLAGS = "-C relocation-model=static";

            postFixup = (old.postFixup or "") + ''
              rm -f $out/nix-support/propagated-build-inputs
              nuke-refs $out/bin/bunker
            '';
          });

          bunker-client-static = self'.packages.bunker-static.override {
            clientOnly = true;
          };
        };
      })
    ]);
  };
}
