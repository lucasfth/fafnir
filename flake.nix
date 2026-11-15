{
  description = "Fafnir: repository secrets with SOPS and age";

  # Fafnir needs Go 1.27, which is newer than the FlakeHub weekly nixpkgs.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      version = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.buildGoModule {
          pname = "fafnir";
          inherit version;
          src = self;
          subPackages = [ "cmd/fafnir" ];
          vendorHash = "sha256-2BtB2fwjI4DKMg7/YG97cQQrXEOWCLu8JwPhEqubcK4=";
          # macOS keychain support needs CGO; buildGoModule enables it by default.
          env.CGO_ENABLED = "1";
          ldflags = [
            "-X github.com/lucasfth/fafnir/internal/cli.Version=${version}"
          ];
          # CI runs the race suite; the Nix sandbox has no keychain or Secret Service.
          doCheck = false;
          meta = {
            description = "Repository secrets with SOPS and age";
            homepage = "https://github.com/lucasfth/fafnir";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "fafnir";
          };
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.default}/bin/fafnir";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.go_1_27 ]; };
      });
    };
}
