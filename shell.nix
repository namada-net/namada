{ pkgs ? import<nixpkgs> {} }: pkgs.mkShell{
  nativeBuildInputs = with pkgs; [pkg-config rustPlatform.bindgenHook];
  buildInputs = with pkgs; [systemdMinimal.dev libclang.lib];
  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
}
