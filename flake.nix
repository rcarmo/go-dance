{
  description = "dance certificate authority wrapper";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # GO-2026-6859: retain the locked package set, but pin the fixed compiler.
      goFor =
        pkgs:
        pkgs.go_1_27.overrideAttrs (old: {
          version = "1.27.4";
          # Bootstrap Go predates container CPU-awareness. Respect Nix's budget.
          preBuild = (old.preBuild or "") + ''
            export GOMAXPROCS=$NIX_BUILD_CORES
            export GOFLAGS="-p=$NIX_BUILD_CORES"
            export GOMEMLIMIT=768MiB
          '';
          src = pkgs.fetchurl {
            url = "https://go.dev/dl/go1.27.4.src.tar.gz";
            hash = "sha256-c8+4VxrsDAEXdofbhxY9Rqog6XeWcncokaoXZU2aYJk=";
          };
        });
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          dance = (pkgs.buildGo127Module.override { go = goFor pkgs; }) {
            pname = "dance";
            version = "0.3.0";
            src = pkgs.lib.cleanSource ./.;
            vendorHash = "sha256-h2+tWnJK83zhS/9t48jQ6MmHUyqLcaQUpElaFGbJfIQ=";
            subPackages = [
              "cmd/dance"
            ];
            env.CGO_ENABLED = "0";
            ldflags = [
              "-s"
              "-w"
            ];
            nativeBuildInputs = [ pkgs.gnumake ];
            # The regression test generates executable shell helpers at runtime.
            postPatch = ''
              substituteInPlace scripts/test-release-config.sh \
                --replace-fail '#!/usr/bin/env bash' '#!${pkgs.runtimeShell}'
            '';
            checkPhase = ''
              runHook preCheck
              export GOFLAGS="''${GOFLAGS//-trimpath/} -p=$NIX_BUILD_CORES"
              make test
              runHook postCheck
            '';
            meta = {
              description = "Local-first web wrapper around an embedded private certificate authority";
              homepage = "https://github.com/rcarmo/go-dance";
              mainProgram = "dance";
              platforms = systems;
            };
          };
        in
        {
          inherit dance;
          default = dance;
        }
      );

      apps = nixpkgs.lib.genAttrs systems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/dance";
          meta.description = self.packages.${system}.default.meta.description;
        };
      });

      checks = nixpkgs.lib.genAttrs systems (system: {
        package = self.packages.${system}.default;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (goFor pkgs)
            pkgs.gnumake
            pkgs.git
            pkgs.openssl
          ];
          GOTOOLCHAIN = "local";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
