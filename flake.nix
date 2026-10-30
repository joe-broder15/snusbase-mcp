{
  description = "Typed Python client for the documented Snusbase API";

  # Pinned to nixos-unstable rev 3ec636362e1816bc2f0888fa0fa2c69f1bc9e504.
  # A branch URL needs the GitHub commits API; this rev is fetched as a tarball.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/3ec636362e1816bc2f0888fa0fa2c69f1bc9e504";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      eachSystem = f: lib.genAttrs systems (system: f system);

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      # Add build-system / package overrides here only when a locked dep needs them.
      pyprojectOverrides = _final: _prev: { };

      mkPythonSet =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              pyprojectOverrides
            ]
          );
    in
    {
      # Impure uv shell: `uv run` syncs from uv.lock. Keeps UV_PYTHON_DOWNLOADS=never
      # and pins the interpreter to nixpkgs python312. An editable uv2nix shell would
      # conflict with `uv run` (UV_NO_SYNC), which we still want for local/CI parity.
      devShells = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.python312
              pkgs.uv
              pkgs.cacert
            ];
            env = {
              UV_PYTHON = "${pkgs.python312}/bin/python";
              UV_PYTHON_DOWNLOADS = "never";
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            };
          };
        }
      );

      packages = eachSystem (
        system:
        let
          pythonSet = mkPythonSet system;
        in
        {
          default = pythonSet."snusbase-client";
        }
      );

      # Lockfile-faithful checks: pytest and ruff come from the uv.lock virtualenv
      # (workspace + dependency group `dev`), not from nixpkgs Python packages.
      checks = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = mkPythonSet system;
          # Project + default deps + dependency groups (includes `dev`: pytest, ruff, …).
          checkEnv = pythonSet.mkVirtualEnv "snusbase-client-check-env" workspace.deps.groups;
        in
        {
          ruff = pkgs.runCommand "snusbase-client-ruff" { nativeBuildInputs = [ checkEnv ]; } ''
            cd ${./.}
            ruff check --no-cache src tests
            ruff format --check --no-cache src tests
            touch $out
          '';

          pytest =
            pkgs.runCommand "snusbase-client-pytest"
              {
                nativeBuildInputs = [
                  checkEnv
                  pkgs.cacert
                ];
              }
              ''
                set -euo pipefail
                # The stdenv points SSL_CERT_FILE at a missing placeholder. httpx
                # loads it when a client is constructed, including under respx.
                export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                export NIX_SSL_CERT_FILE="$SSL_CERT_FILE"
                cp -a ${./.} src-tree
                chmod -R u+w src-tree
                cd src-tree
                export PYTHONDONTWRITEBYTECODE=1
                # Import the installed package from checkEnv (not PYTHONPATH=src).
                pytest -q -p no:cacheprovider
                touch $out
              '';
        }
      );
    };
}
