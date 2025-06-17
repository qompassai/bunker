let
  flake = import ./flake-compat.nix;
in flake.defaultNix.default.overrideAttrs (_: {
  passthru = {
    bunker-client = flake.defaultNix.outputs.packages.${builtins.currentSystem}.bunker-client;
    demo = flake.defaultNix.outputs.devShells.${builtins.currentSystem}.demo;
  };
})
