# /qompassai/bunker/flake/overlays.nix
# Qompass AI Bunker Overlay Flake
{ makeCranePkgs, ... }:
{
  flake.overlays = {
    default = final: prev: let
      cranePkgs = makeCranePkgs final;
    in {
      inherit (cranePkgs)
        bunker
        bunker-client
        bunker-server
        ;
    };
  };
}
