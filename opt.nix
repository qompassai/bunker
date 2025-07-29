# /qompassai/bunker/opt.nix
# Qompass AI Bunker Opts
# Copyright (C) 2025 Qompass AI, All rights reserved
{ inputs, ... }: {
  perSystem = { config, self', inputs', pkgs, system, lib, ... }: {
    packages = {
      bunker-server-optimized = inputs.crane.lib.${system}.buildPackage {
        src = ./.;
        cargoExtraArgs = "--release";
        CARGO_BUILD_RUSTFLAGS = [
          "-C target-cpu=native"
          "-C link-arg=-fuse-ld=mold"
          "-C codegen-units=1"
          "-C lto=fat"
          "-C panic=abort"
        ];
        nativeBuildInputs = with pkgs; [
          mold
          upx
        ];
        postInstall = ''
          ${pkgs.binutils}/bin/strip $out/bin/*
          ${pkgs.upx}/bin/upx --best $out/bin/* || true
        '';
      };
      container-image = pkgs.dockerTools.buildLayeredImage {
        name = "bunker-server";
        tag = "latest";
        contents = [ self'.packages.bunker-server-optimized ];
        config = {
          Cmd = [ "/bin/bunker-server" ];
          ExposedPorts = { "8080/tcp" = {}; };
          User = "65534:65534";
          WorkingDir = "/tmp";
          Memory = "512m";
          MemorySwap = "512m";
          CpuShares = 1024;
        };
        maxLayers = 20;
      };
    };
    apps = {
      benchmark = {
        type = "app";
        program = pkgs.writeShellScript "benchmark" ''
          echo "🚀 Running performance benchmarks..."
          ${pkgs.wrk}/bin/wrk -t12 -c400 -d30s http://localhost:8080/
          ${pkgs.valgrind}/bin/valgrind --tool=massif ./result/bin/bunker-server &
          ${pkgs.perf-tools}/bin/perf record -g ./result/bin/bunker-server
        '';
      };
      monitor = {
        type = "app";
        program = pkgs.writeShellScript "monitor" ''
          echo "📊 Starting monitoring stack..."
          ${pkgs.prometheus-node-exporter}/bin/node_exporter &
          ${pkgs.grafana-agent}/bin/agent &
          echo "Monitoring available on ports 9100 (metrics) and 3000 (grafana)"
        '';
      };
    };
  };
  flake.nixosModules.bunker-server = { config, lib, pkgs, ... }: {
    options.services.bunker-server = {
      enable = lib.mkEnableOption "Bunker binary cache server";
      optimization = {
        enableJemalloc = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Use jemalloc for better memory management";
        };
        maxConnections = lib.mkOption {
          type = lib.types.int;
          default = 1000;
          description = "Maximum concurrent connections";
        };
      };
      security = {
        enableFirewall = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Enable firewall rules";
        };
        enableTLS = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Enable TLS encryption";
        };
      };
    };
    config = lib.mkIf config.services.bunker-server.enable {
      security.apparmor.enable = true;
      security.audit.enable = true;
      boot.kernel.sysctl = {
        "net.core.rmem_max" = 268435456;
        "net.core.wmem_max" = 268435456;
        "net.ipv4.tcp_congestion_control" = "bbr";
        "vm.swappiness" = 10;
      };
      systemd.services.bunker-server = {
        serviceConfig = {
          MemoryMax = "2G";
          TasksMax = 4096;
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
        };
      };
      services.prometheus.exporters.node.enable = true;
      services.grafana.enable = true;
    };
  };
}
