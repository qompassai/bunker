{ config, ... }:
{
  flake.nixosModules = {
    bunker-proxy = {
      imports = [
        ../nixos/bunker-proxy.nix
      ];

      nixpkgs.overlays = [
        config.flake.overlays.default
      ];
    };

    bunkerd = {
      imports = [
        ../nixos/bunkerd.nix
      ];

      services.bunkerd.useFlakeCompatOverlay = false;

      nixpkgs.overlays = [
        config.flake.overlays.default
      ];
    };
  };
}
