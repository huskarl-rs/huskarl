{
  inputs = {
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    fenix.url = "github:nix-community/fenix";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs-lib";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    nixpkgs-lib.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-substituters = [ "https://fenix.cachix.org" ];
    extra-trusted-public-keys = [
      "fenix.cachix.org-1:ecJhr+RdYEdcVgUkjruiYhjbBloIEGov7bos90cZi0Q="
    ];
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-darwin"
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      imports = [ inputs.treefmt-nix.flakeModule ];
      perSystem =
        {
          inputs',
          lib,
          pkgs,
          self',
          ...
        }:
        let
          fmtt = pkgs.writeShellApplication {
            name = "fmtt";
            text = ''${lib.getExe self'.formatter} "$@"'';
          };
          rustPkgs = inputs'.fenix.packages.stable;
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [
              fmtt
              pkgs.cargo-llvm-cov
              pkgs.cargo-msrv
              pkgs.cargo-readme
              pkgs.nixd
              pkgs.sqlite
              pkgs.sqlite-analyzer
              rustPkgs.toolchain
            ];
            RUST_SRC_PATH = "${rustPkgs.rust-src}/lib/rustlib/src/rust/library";
          };
          treefmt = {
            projectRootFile = ".envrc";
            programs = {
              nixfmt.enable = true;
              rustfmt = {
                enable = true;
                package = inputs'.fenix.packages.latest.rustfmt;
              };
            };
          };
        };
    };
}
