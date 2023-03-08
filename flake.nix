{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      overlays = [ rust-overlay.overlays.default ];
      pkgs = import nixpkgs { inherit system overlays; };
      rust = pkgs.rust-bin.fromRustupToolchainFile ./client/rust-toolchain.toml;
    in
      {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            (pkgs.writeShellScriptBin "vscode-html-language-server" "exec -a $0 ${nodePackages.vscode-html-languageserver-bin}/bin/html-languageserver $0")
            (pkgs.writeShellScriptBin "vscode-css-language-server" "exec -a $0 ${nodePackages.vscode-css-languageserver-bin}/bin/css-languageserver $0")
            nodePackages.prettier
            rust-analyzer
            wasm-pack
            wasm-bindgen-cli
            binaryen
            go_1_20
            gopls
          ] ++ [ rust ];
        };
      }
    );
}
