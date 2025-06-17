#!/usr/bin/env bash
set -euo pipefail
expr=$(mktemp)

cleanup() {
    rm -f "$expr"
}

cat >"$expr" <<'EOF'
  { system ? builtins.currentSystem }:
let
  maybeStorePath = if builtins ? langVersion && builtins.lessThan 1 builtins.langVersion
    then builtins.storePath
    else x: x;
  mkFakeDerivation = attrs: outputs:
    let
      outputNames = builtins.attrNames outputs;
      common = attrs // outputsSet //
        { type = "derivation";
          outputs = outputNames;
          all = outputsList;
        };
      outputToAttrListElement = outputName:
        { name = outputName;
          value = common // {
            inherit outputName;
            outPath = maybeStorePath (builtins.getAttr outputName outputs);
          };
        };
      outputsList = map outputToAttrListElement outputNames;
      outputsSet = builtins.listToAttrs outputsList;
    in outputsSet;
in

{
  "x86_64-linux" = (mkFakeDerivation {
  name = "bunker-static-x86_64-unknown-linux-musl-0.1.0";
  system = "x86_64-linux";
} {
  out = "/nix/store/qi9cixkq0pj60yw1y5l28hid7f53310i-bunker-static-x86_64-unknown-linux-musl-0.1.0";
}).out;

  "aarch64-linux" = (mkFakeDerivation {
  name = "bunker-0.1.0";
  system = "aarch64-linux";
} {
  out = "/nix/store/ng1aykmyk7ayzrn69hlv4n4qzbywj5rk-bunker-0.1.0";
}).out;

  "x86_64-darwin" = (mkFakeDerivation {
  name = "bunker-0.1.0";
  system = "x86_64-darwin";
} {
  out = "/nix/store/zh35fhdyxnxzp1mjyla95g2yv2ayzc3f-bunker-0.1.0";
}).out;

  "aarch64-darwin" = (mkFakeDerivation {
  name = "bunker-0.1.0";
  system = "aarch64-darwin";
} {
  out = "/nix/store/z9i4grsf3h0wdlbhg95v6nanxiqx5xvp-bunker-0.1.0";
}).out;

}.${system}

EOF

nix-env --substituters "https://staging.bunker.rs/bunker-ci https://cache.nixos.org" --trusted-public-keys "bunker-ci:U5Sey4mUxwBXM3iFapmP0/ogODXywKLRNgRPQpEXxbo= cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" -if "$expr"
