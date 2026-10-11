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
        # Throwaway Ed25519 key, generated solely so this build-time check
        # exercises the same configuration code path as production. It is
        # not a real secret and is never used at runtime: production keys
        # come from services.bunkerd.environmentFile.
        export BUNKER_SERVER_TOKEN_ED25519_SECRET_BASE64="LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUxpdlM2bDZvYzZTeWZYcnk1YUpsZmtYZEVnblZCQnVjOFg1K3VTWEFiMmUKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="
        ${lib.optionalString (cfg.signing.hybridSecretKeyFile != null) ''
          # The real hybrid secret key is not (and must not be) available
          # inside the build sandbox. Generate a throwaway key with the
          # configured name and check a copy of the configuration against
          # it; the checked output below still references the real path,
          # and the real key is validated at service start (preStart).
          cp $configFile config.toml
          chmod u+w config.toml
          ${cfg.package}/bin/bunkeradm generate-hybrid-key --name '${cfg.signing.hybridKeyName}' > hybrid-secret.key
          sed -i "s|${cfg.signing.hybridSecretKeyFile}|$PWD/hybrid-secret.key|" config.toml
          configFile=config.toml
        ''}
        export BUNKER_SERVER_DATABASE_URL="sqlite://:memory:"
        ${cfg.package}/bin/bunkerd --mode check-config -f $configFile
        cat <${cfg.configFile} >$out
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

          - BUNKER_SERVER_TOKEN_ED25519_SECRET_BASE64: The base64-encoded Ed25519 PEM PKCS#8 of the
            Ed25519 JWT secret. Generate it with
            `openssl genpkey -algorithm ED25519 -out private_key.pem` and encode with `base64 -w0 private_key.pem`.
            Used for signing and verifying JWTs.

          Alternatively, on verify-only nodes:

          - BUNKER_SERVER_TOKEN_ED25519_PUBKEY_BASE64: The base64-encoded Ed25519 PEM public key.
            Used for verifying JWTs only (no signing).

          - BUNKER_SERVER_DATABASE_URL: The database connection string (for
            example `postgres://bunkerd@db.example.org/bunker`). Only
            required when `services.bunkerd.settings.database.url` is not
            set in the configuration.
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

      signing = {
        hybridKeyName = lib.mkOption {
          description = ''
            Name of the hybrid (Ed25519 + ML-DSA-65) signing key used to
            sign cache narinfos.

            Must match the name embedded in the key file given by
            `services.bunkerd.signing.hybridSecretKeyFile`. The server
            refuses to start if the names differ.

            When unset (the default), caches are signed with per-cache
            keys generated by the server's first-run setup and stored in
            the database.
          '';
          type = types.nullOr types.str;
          default = null;
          example = "<PLACEHOLDER:hybrid-key-name>";
        };

        hybridSecretKeyFile = lib.mkOption {
          description = ''
            Path to a file containing the hybrid secret key in canonical
            format (`{name}:{base64}` over a 96-byte payload: a 64-byte
            Ed25519 keypair followed by a 32-byte ML-DSA-65 seed).
            Generate one with `bunkeradm generate-hybrid-key`.

            The file is read by the server at startup and validated on
            every start. It must not be a path in the Nix store.
          '';
          type = types.nullOr types.path;
          default = null;
          example = "<PLACEHOLDER:hybrid-secret-key-file>";
        };
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

          Run `openssl genpkey -algorithm ED25519 -out private_key.pem` and create a file with the following contents:

          BUNKER_SERVER_TOKEN_ED25519_SECRET_BASE64=<output of `base64 -w0 private_key.pem`>

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
      {
        assertion =
          (cfg.signing.hybridKeyName == null) == (cfg.signing.hybridSecretKeyFile == null);
        message = ''
          <option>services.bunkerd.signing.hybridKeyName</option> and
          <option>services.bunkerd.signing.hybridSecretKeyFile</option> must be set together, or both left unset.
        '';
      }
      {
        assertion =
          cfg.signing.hybridSecretKeyFile == null || !lib.isStorePath cfg.signing.hybridSecretKeyFile;
        message = ''
          <option>services.bunkerd.signing.hybridSecretKeyFile</option> points to a path in the Nix store. The Nix store is globally readable.

          You should use a quoted absolute path to prevent leaking secrets in the Nix store.
        '';
      }
    ];

    services.bunkerd.settings = {
      database.url = lib.mkDefault "sqlite:///var/lib/bunkerd/server.db?mode=rwc";

      signing = lib.mkIf (cfg.signing.hybridSecretKeyFile != null) {
        hybrid-key-name = cfg.signing.hybridKeyName;
        hybrid-secret-key-file = cfg.signing.hybridSecretKeyFile;
      };

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
      # Re-validates the configuration with the real EnvironmentFile
      # loaded (systemd applies EnvironmentFile to ExecStartPre too), so
      # the real JWT and hybrid keys are checked on every start, not just
      # the build-time dummy keys in checkedConfigFile.
      preStart = ''
        ${cfg.package}/bin/bunkerd --mode check-config -f ${checkedConfigFile}
      '';
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
