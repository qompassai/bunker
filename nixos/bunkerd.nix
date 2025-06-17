{
  lib,
  pkgs,
  config,
  ...
}:
let
  inherit (lib) types;
  cfg = config.services.bunkerd;
  flake = import ../flake-compat.nix;
  overlay = flake.defaultNix.overlays.default;
  format = pkgs.formats.toml { };
  checkedConfigFile =
    pkgs.runCommand "checked-bunker-server.toml"
      {
        configFile = cfg.configFile;
      }
      ''
        cat $configFile
        export BUNKER_SERVER_TOKEN_HS256_SECRET_BASE64="dGVzdCBzZWNyZXQ="
        export BUNKER_SERVER_DATABASE_URL="sqlite://:memory:"
        ${cfg.package}/bin/bunkerd --mode check-config -f $configFile
        cat <$configFile >$out
      '';
  bunkeradmShim = pkgs.writeShellScript "bunkeradm" ''
    if [ -n "$BUNKERADM_PWD" ]; then
      cd "$BUNKERADM_PWD"
      if [ "$?" != "0" ]; then
        >&2 echo "Warning: Failed to change directory to $BUNKERADM_PWD"
      fi
    fi
    exec ${cfg.package}/bin/bunkeradm -f ${checkedConfigFile} "$@"
  '';
  bunkeradmWrapper = pkgs.writeShellScriptBin "bunkerd-bunkeradm" ''
    exec systemd-run \
      --quiet \
      --pipe \
      --pty \
      --wait \
      --collect \
      --service-type=exec \
      --property=EnvironmentFile=${cfg.environmentFile} \
      --property=DynamicUser=yes \
      --property=User=${cfg.user} \
      --property=Environment=BUNKERADM_PWD=$(pwd) \
      --working-directory / \
      -- \
      ${bunkeradmShim} "$@"
  '';

  hasLocalPostgresDB =
    let
      url = cfg.settings.database.url or "";
      localStrings = [
        "localhost"
        "127.0.0.1"
        "/run/postgresql"
      ];
      hasLocalStrings = lib.any (lib.flip lib.hasInfix url) localStrings;
    in
    config.services.postgresql.enable && lib.hasPrefix "postgresql://" url && hasLocalStrings;
in
{
  imports = [
    (lib.mkRenamedOptionModule [ "services" "bunkerd" "credentialsFile" ] [ "services" "bunkerd" "environmentFile" ])
  ];

  options = {
    services.bunkerd = {
      enable = lib.mkEnableOption "the bunkerd, the Secure Nix Binary Cache Server";

      package = lib.mkPackageOption pkgs "bunker-server" { };

      environmentFile = lib.mkOption {
        description = ''
          Path to an EnvironmentFile containing required environment
          variables:

          - BUNKER_SERVER_TOKEN_RS256_SECRET_BASE64: The base64-encoded RSA PEM PKCS1 of the
            RS256 JWT secret. Generate it with `openssl genrsa -traditional 4096 | base64 -w0`.
        '';
        type = types.nullOr types.path;
        default = null;
      };

      user = lib.mkOption {
        description = ''
          The group under which bunker runs.
        '';
        type = types.str;
        default = "bunkerd";
      };

      group = lib.mkOption {
        description = ''
          The user under which bunker runs.
        '';
        type = types.str;
        default = "bunkerd";
      };

      settings = lib.mkOption {
        description = ''
          Structured configurations of bunkerd.
        '';
        type = format.type;
        default = { };
      };

      configFile = lib.mkOption {
        description = ''
          Path to an existing bunkerd configuration file.

          By default, it's generated from `services.bunkerd.settings`.
        '';
        type = types.path;
        default = format.generate "server.toml" cfg.settings;
        defaultText = "generated from `services.bunkerd.settings`";
      };

      mode = lib.mkOption {
        description = ''
          Mode in which to run the server.

          'monolithic' runs all components, and is suitable for single-node deployments.

          'api-server' runs only the API server, and is suitable for clustering.

          'garbage-collector' only runs the garbage collector periodically.

          A simple NixOS-based Bunker deployment will typically have one 'monolithic' and any number of 'api-server' nodes.

          There are several other supported modes that perform one-off operations, but these are the only ones that make sense to run via the NixOS module.
        '';
        type = lib.types.enum [
          "monolithic"
          "api-server"
          "garbage-collector"
        ];
        default = "monolithic";
      };
      useFlakeCompatOverlay = lib.mkOption {
        description = ''
          Whether to insert the overlay with flake-compat.
        '';
        type = types.bool;
        internal = true;
        default = true;
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.environmentFile != null;
        message = ''
          <option>services.bunkerd.environmentFile</option> is not set.

          Run `openssl genrsa -traditional -out private_key.pem 4096 | base64 -w0` and create a file with the following contents:

          BUNKER_SERVER_TOKEN_RS256_SECRET="output from command"

          Then, set `services.bunkerd.environmentFile` to the quoted absolute path of the file.
        '';
      }
      {
        assertion = !lib.isStorePath cfg.environmentFile;
        message = ''
          <option>services.bunkerd.environmentFile</option> points to a path in the Nix store. The Nix store is globally readable.

          You should use a quoted absolute path to prevent leaking secrets in the Nix store.
        '';
      }
    ];

    services.bunkerd.settings = {
      database.url = lib.mkDefault "sqlite:///var/lib/bunkerd/server.db?mode=rwc";

      storage = lib.mkDefault {
        type = "local";
        path = "/var/lib/bunkerd/storage";
      };
    };

    systemd.services.bunkerd = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ] ++ lib.optionals hasLocalPostgresDB [ "postgresql.service" ];
      requires = lib.optionals hasLocalPostgresDB [ "postgresql.service" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/bunkerd -f ${checkedConfigFile} --mode ${cfg.mode}";
        EnvironmentFile = cfg.environmentFile;
        StateDirectory = "bunkerd";
        DynamicUser = true;
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = 10;
        CapabilityBoundingSet = [ "" ];
        DeviceAllow = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        PrivateUsers = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadWritePaths =
          let
            path = cfg.settings.storage.path;
            isDefaultStateDirectory = path == "/var/lib/bunkerd" || lib.hasPrefix "/var/lib/bunkerd/" path;
          in
          lib.optionals (cfg.settings.storage.type or "" == "local" && !isDefaultStateDirectory) [ path ];
        RemoveIPC = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@resources"
          "~@privileged"
        ];
        UMask = "0077";
      };
    };

    environment.systemPackages = [
      bunkeradmWrapper
    ];
    nixpkgs.overlays = lib.mkIf cfg.useFlakeCompatOverlay [
      overlay
    ];
  };
}
