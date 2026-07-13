{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        liquidElectrsOverlay = final: prev: {
          blockstream-electrs = prev.blockstream-electrs.overrideAttrs (old: {
            cargoBuildFlags = (old.cargoBuildFlags or [ ]) ++ [ "--features=liquid" ];
            doCheck = false;
          });
        };
        pkgsUnstable = import nixpkgs-unstable {
          inherit system;
          overlays = [ liquidElectrsOverlay ];
        };
        lib = pkgs.lib;
        rustToolchain = with pkgsUnstable; [
          cargo
          clippy
          rustc
          rustfmt
        ];
        smplx = pkgsUnstable.rustPlatform.buildRustPackage rec {
          pname = "smplx";
          version = "0.0.6";
          src = pkgs.fetchgit {
            url = "https://github.com/BlockstreamResearch/smplx.git";
            rev = "97782c796fbb4f2845f6fdb9dfb8d5a228dc8f2c";
            hash = "sha256-g93UmL7P4gU5KpwT7s5OCHv0pqiCrIzzX1qxaSqFniE=";
            fetchSubmodules = false;
          };
          cargoLock.lockFile = ./nix/smplx-Cargo.lock;
          buildAndTestSubdir = "crates/cli";
          doCheck = false;
          meta.mainProgram = "simplex";
        };
      in
      {
        packages.simplex = smplx;

        checks.simplex-version = pkgs.runCommand "deadcat-simplex-version" {
          nativeBuildInputs = [ smplx ];
        } ''
          simplex --version | grep -F "0.0.6"
          touch $out
        '';

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            just
            git
            pkg-config
            cargo-nextest
          ] ++ [
            smplx
            pkgsUnstable.elementsd
            pkgsUnstable.blockstream-electrs
          ] ++ rustToolchain
          ++ lib.optionals pkgs.stdenv.isDarwin (with pkgs; [ libiconv ]);

          # Keep generated Cargo objects outside the source tree. Besides making
          # clean checkouts reproducible, this prevents `nix develop path:.`
          # (needed before an initial commit) from recursively copying a large
          # `target/` directory into the Nix store on every invocation.
          shellHook = ''
            export CARGO_TARGET_DIR="''${DEADCAT_CARGO_TARGET_DIR:-/tmp/deadcat-node-target}"
          '' + lib.optionalString pkgs.stdenv.isDarwin ''
            if [ -x /usr/bin/xcode-select ]; then
              _deadcat_xcode_dev="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
              if [ -n "$_deadcat_xcode_dev" ] && [ -d "$_deadcat_xcode_dev" ]; then
                export DEVELOPER_DIR="$_deadcat_xcode_dev"
                export PATH="/usr/bin:$PATH"
              fi
              unset _deadcat_xcode_dev
            fi
          '';
        };
      });
}
