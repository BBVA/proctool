{ pkgs ? import (builtins.fetchGit {
    name = "nixos-20.03";
    url = "https://github.com/nixos/nixpkgs-channels/";
    ref = "refs/heads/nixos-20.03";
  }) {}}: 
let
  pythonDependencies = pypackages: with pypackages; [
    hypothesis
    pytest
  ];
  python38WithDependencies = pkgs.python38.withPackages pythonDependencies;
in
  pkgs.mkShell {
    name = "proctool";
    buildInputs = [
      pkgs.go
      pkgs.gnumake
      pkgs.musl
      pkgs.gcc
      python38WithDependencies
    ];
  }

