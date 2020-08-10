with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "linux-kernel-dev";
  buildInputs = with pkgs; [
    utillinux binutils gnumake which ccache gcc
  ];
  shellHook = ''
    export KDIR="$(nix-build -E '(import <nixpkgs> {}).linux.dev' --no-out-link)/lib/modules/*/build"
  '';
}
