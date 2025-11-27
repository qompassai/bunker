

{ lib, flake-parts-lib, ... }:
let
  inherit (lib)
    mkOption
    types
    ;
in
{
  options = {
    bunker.distributor = mkOption {
      type = types.str;
      default = "dev";
    };
  };
}
