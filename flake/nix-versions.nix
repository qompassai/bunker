{ lib, flake-parts-lib, config, ... }:
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
      options.bunker.nix-versions = {
        versions = mkOption {
          type = types.attrsOf types.package;
          default = {};
        };
        manifestFile = mkOption {
          type = types.package;
        };
      };

      options.internalMatrix = mkOption {
        type = types.attrsOf (types.attrsOf types.package);
      };
    };
  };

  config = {
    flake.internalMatrix = lib.mapAttrs (system: ps: ps.internalMatrix) config.allSystems;

    perSystem = { self', pkgs, config, cranePkgs, ... }: let
      cfg = config.bunker.nix-versions;
    in {
      bunker.nix-versions = {
        versions = {
          default = pkgs.nix;
          "2.20" = pkgs.nixVersions.nix_2_20;
          "2.24" = pkgs.nixVersions.nix_2_24;
        };

        manifestFile = let
          manifest = lib.mapAttrs (_: nix: {
            inherit nix;
            shellHook = ''
              export NIX_INCLUDE_PATH="${lib.getDev nix}/include"
              export NIX_CFLAGS_COMPILE="-isystem $NIX_INCLUDE_PATH $NIX_CFLAGS_COMPILE"
              export NIX_LDFLAGS="-L${nix}/lib $NIX_LDFLAGS"
              export PKG_CONFIG_PATH="${lib.getDev nix}/lib/pkgconfig:$PKG_CONFIG_PATH"
              export PATH="${lib.getBin nix}/bin:$PATH"
            '';
          }) cfg.versions;
        in pkgs.writeText "nix-versions.json" (builtins.toJSON manifest);
      };

      internalMatrix = lib.mapAttrs (_: nix: let
        cranePkgs' = cranePkgs.override { inherit nix; };
      in {
        inherit (cranePkgs') bunker-tests cargoArtifacts;
      }) cfg.versions;
    };
  };
}
