{
  lib,
  pkgs,
  config,
  ...
}:
let
  inherit (lib) types;
  cfg = config.services.bunker-proxy;

  acmeCertDirectory = config.security.acme.certs.${cfg.useACMEHost}.directory;

  certFile =
    if cfg.useACMEHost != null then "${acmeCertDirectory}/fullchain.pem" else cfg.certificateFile;
  keyFile = if cfg.useACMEHost != null then "${acmeCertDirectory}/key.pem" else cfg.keyFile;
in
{
  options = {
    services.bunker-proxy = {
      certificateFile = lib.mkOption {
        description = ''
          Path to the TLS certificate file (PEM, full chain) served by the
          proxy.

          Must be set together with
          `services.bunker-proxy.keyFile`, and is mutually exclusive with
          `services.bunker-proxy.useACMEHost`: exactly one TLS source must
          be configured.

          Must not be a path in the Nix store.
        '';
        type = types.nullOr types.path;
        default = null;
        example = "<PLACEHOLDER:proxy-certificate-file>";
      };

      enable = lib.mkEnableOption "the bunker-proxy, the TLS-terminating reverse proxy for bunkerd";

      keyFile = lib.mkOption {
        description = ''
          Path to the TLS private key file (PEM) used by the proxy.

          Must be set together with
          `services.bunker-proxy.certificateFile`, and is mutually
          exclusive with `services.bunker-proxy.useACMEHost`: exactly one
          TLS source must be configured.

          Must not be a path in the Nix store.
        '';
        type = types.nullOr types.path;
        default = null;
        example = "<PLACEHOLDER:proxy-key-file>";
      };

      listen = lib.mkOption {
        description = ''
          Address the proxy listens on.
        '';
        type = types.str;
        default = "[::]:4430";
      };

      package = lib.mkPackageOption pkgs "bunker-proxy" { };

      rateLimitBurst = lib.mkOption {
        description = ''
          Rate limit burst capacity per client IP.
        '';
        type = types.ints.positive;
        default = 200;
      };

      rateLimitRps = lib.mkOption {
        description = ''
          Rate limit in requests per second per client IP.
        '';
        type = types.ints.positive;
        default = 100;
      };

      upstream = lib.mkOption {
        description = ''
          Address of the bunkerd upstream the proxy forwards to.
        '';
        type = types.str;
        default = "127.0.0.1:8080";
      };

      useACMEHost = lib.mkOption {
        description = ''
          Name of an ACME certificate (as in
          `security.acme.certs.<name>`) whose certificate and key the proxy
          serves.

          Mutually exclusive with
          `services.bunker-proxy.certificateFile` and
          `services.bunker-proxy.keyFile`: exactly one TLS source must be
          configured.
        '';
        type = types.nullOr types.str;
        default = null;
        example = "<PLACEHOLDER:cache-host>";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.certificateFile == null) == (cfg.keyFile == null);
        message = ''
          <option>services.bunker-proxy.certificateFile</option> and
          <option>services.bunker-proxy.keyFile</option> must be set together, or both left unset.
        '';
      }
      {
        assertion = (cfg.useACMEHost != null) != (cfg.certificateFile != null);
        message = ''
          Exactly one TLS source must be configured for <option>services.bunker-proxy</option>:
          either <option>services.bunker-proxy.useACMEHost</option>, or both
          <option>services.bunker-proxy.certificateFile</option> and
          <option>services.bunker-proxy.keyFile</option> — never neither, never both.
        '';
      }
      {
        assertion = cfg.certificateFile == null || !lib.isStorePath cfg.certificateFile;
        message = ''
          <option>services.bunker-proxy.certificateFile</option> points to a path in the Nix store. The Nix store is globally readable.

          You should use a quoted absolute path for TLS material.
        '';
      }
      {
        assertion = cfg.keyFile == null || !lib.isStorePath cfg.keyFile;
        message = ''
          <option>services.bunker-proxy.keyFile</option> points to a path in the Nix store. The Nix store is globally readable.

          You should use a quoted absolute path to prevent leaking secrets in the Nix store.
        '';
      }
    ];

    systemd.services.bunker-proxy = {
      wantedBy = [ "multi-user.target" ];
      after =
        [
          "network-online.target"
        ]
        ++ lib.optionals config.services.bunkerd.enable [ "bunkerd.service" ]
        ++ lib.optionals (cfg.useACMEHost != null) [ "acme-${cfg.useACMEHost}.service" ];
      wants = [
        "network-online.target"
      ] ++ lib.optionals (cfg.useACMEHost != null) [ "acme-${cfg.useACMEHost}.service" ];
      environment = {
        BUNKER_PROXY_RATE_LIMIT_BURST = toString cfg.rateLimitBurst;
        BUNKER_PROXY_RATE_LIMIT_RPS = toString cfg.rateLimitRps;
      };
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/bunker-proxy --listen ${cfg.listen} --tls-cert ${certFile} --tls-key ${keyFile} --upstream ${cfg.upstream}";
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 10;
        StateDirectory = "bunker-proxy";
        # ACME keys are owned by the acme group; the dynamic user needs it
        # to read the certificate directory on the ACME route.
        SupplementaryGroups = lib.optionals (cfg.useACMEHost != null) [ "acme" ];
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
  };
}
