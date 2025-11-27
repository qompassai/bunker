# /qompassai/bunker/package.nix
# Qompass AI Bunker Nix Package
#
{ lib, stdenv, rustPlatform
, pkg-config
, installShellFiles
, nix
, boost
, darwin
, clientOnly ? false
, crates ? if clientOnly then [ "bunker-client" ] else [ "bunker-client" "bunker-server" ]
}:
let
  ignoredPaths = [ ".github" "target" "book" ];
in rustPlatform.buildRustPackage rec {
  pname = "bunker";
  version = "0.1.0";
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
  ] ++ lib.optionals stdenv.isDarwin (with darwin.apple_sdk.frameworks; [
    SystemConfiguration
  ]);
  cargoLock = {
    lockFile = ./Cargo.lock;
    allowBuiltinFetchGit = true;
  };
  cargoBuildFlags = lib.concatMapStrings (c: "-p ${c} ") crates;
  BUNKER_DISTRIBUTOR = "bunker";
  NIX_INCLUDE_PATH = "${lib.getDev nix}/include";
  doCheck = false;
  postInstall = lib.optionalString (stdenv.hostPlatform == stdenv.buildPlatform) ''
    if [[ -f $out/bin/bunker ]]; then
      installShellCompletion --cmd bunker \
        --bash <($out/bin/bunker gen-completions bash) \
        --zsh <($out/bin/bunker gen-completions zsh) \
        --fish <($out/bin/bunker gen-completions fish)
    fi
  '';
  meta = with lib; {
    description = "Quality Nix binary cache system";
    homepage = "https://github.com/qompassai/bunker";
    license = licenses.asl20;
    maintainers = with maintainers; [ phaedrusflow ];
    platforms = platforms.linux ++ platforms.darwin;
    mainProgram = "bunker";
  };
}
