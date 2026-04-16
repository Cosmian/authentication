{
  pkgs ? import <nixpkgs> { },
  # Auth server derivation to include in the image
  authServer ? null,
  # Version (from Cargo.toml)
  version,
}:

let
  actualAuthServer =
    if authServer != null then
      authServer
    else
      builtins.throw "authServer parameter is required. Pass it from default.nix";

  imageName = "cosmian-auth-server";
  imageTag = "${version}";

  runtimeEnv = pkgs.buildEnv {
    name = "auth-server-runtime-env";
    paths = [
      actualAuthServer
      pkgs.tzdata
      pkgs.coreutils
      pkgs.bash
    ];
  };

  etcPasswd = pkgs.writeTextFile {
    name = "passwd";
    text = ''
      root:x:0:0:root:/root:/bin/sh
      auth:x:1000:1000:Auth User:/home/auth:/bin/sh
    '';
    destination = "/etc/passwd";
  };

  etcGroup = pkgs.writeTextFile {
    name = "group";
    text = ''
      root:x:0:
      auth:x:1000:
    '';
    destination = "/etc/group";
  };

  etcNsswitch = pkgs.writeTextFile {
    name = "nsswitch.conf";
    text = ''
      hosts: files dns
      networks: files
      passwd: files
      group: files
    '';
    destination = "/etc/nsswitch.conf";
  };

in
pkgs.dockerTools.buildImage {
  name = imageName;
  tag = imageTag;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      runtimeEnv
      etcPasswd
      etcGroup
      etcNsswitch
      pkgs.dockerTools.caCertificates
    ];
    pathsToLink = [
      "/bin"
      "/etc"
      "/usr"
      "/var"
    ];
  };

  config = {
    Cmd = [ "/bin/auth_server" ];
    ExposedPorts = {
      "9005/tcp" = { };
    };
    User = "1000:1000";
    WorkingDir = "/home/auth";
    Labels = {
      "org.opencontainers.image.title" = "Cosmian Authentication Server";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.vendor" = "Cosmian";
    };
  };

  created = "now";
}
