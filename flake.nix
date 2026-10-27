{
  description = "Snusbase API client: OpenAPI spec and typed Python package";

  # Pinned to nixos-unstable rev 3ec636362e1816bc2f0888fa0fa2c69f1bc9e504.
  # A branch URL needs the GitHub commits API; this rev is fetched as a tarball.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/3ec636362e1816bc2f0888fa0fa2c69f1bc9e504";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.python312
            pkgs.uv
            pkgs.ruff
            pkgs.cacert
          ];
          env = {
            UV_PYTHON = "${pkgs.python312}/bin/python";
            UV_PYTHON_DOWNLOADS = "never";
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          };
        };
      });

      # `nix flake check` runs these derivations. pytest here uses nixpkgs
      # Python packages so the sandbox does not need PyPI. The lockfile-
      # faithful suite is `nix develop -c uv run pytest`.
      checks = eachSystem (pkgs: {
        ruff = pkgs.runCommand "snusbase-client-ruff" { nativeBuildInputs = [ pkgs.ruff ]; } ''
          cd ${./.}
          ruff check --no-cache src tests
          ruff format --check --no-cache src tests
          touch $out
        '';

        pytest =
          let
            python = pkgs.python312.withPackages (
              ps: with ps; [
                pytest
                httpx
                pydantic
                respx
                openapi-spec-validator
              ]
            );
          in
          pkgs.runCommand "snusbase-client-pytest" { nativeBuildInputs = [ python pkgs.cacert ]; } ''
            set -euo pipefail
            # The stdenv points SSL_CERT_FILE at a missing placeholder. httpx
            # loads it when a client is constructed, including under respx.
            export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            export NIX_SSL_CERT_FILE="$SSL_CERT_FILE"
            cp -a ${./.} src-tree
            chmod -R u+w src-tree
            cd src-tree
            export PYTHONPATH="$PWD/src"
            export PYTHONDONTWRITEBYTECODE=1
            pytest -q -p no:cacheprovider
            touch $out
          '';
      });
    };
}
