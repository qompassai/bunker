{ config, ... }:
{
  flake.nixosModules = {
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
