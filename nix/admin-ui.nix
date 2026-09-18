{
  pkgs ? import <nixpkgs> { },
  stdenv ? pkgs.stdenv,
  lib ? pkgs.lib,
  # Version (from workspace Cargo.toml)
  version,
}:

let
  # Filter source to exclude generated / ephemeral directories
  sourceFilter =
    path: _type:
    let
      baseName = baseNameOf path;
    in
    baseName != "node_modules"
    && baseName != "dist"
    && baseName != ".git";

  # Inside Nix's real Linux build sandbox, pnpm 9.12.3 loses the `overrides:`
  # block when it parses pnpm-lock.yaml into its internal Lockfile object:
  # `ctx.wantedLockfile.overrides` comes back `undefined` even though the
  # file on disk is untouched and package.json's `pnpm.overrides` parses
  # fine right next to it. Verified extensively (identical pnpm.cjs bytes,
  # identical file content, identical Node 22.10.0 build, sandbox on/off,
  # fresh isolated state, CPU load) — none of it reproduces outside this
  # exact GitHub Actions Linux sandbox, so the root cause is some
  # environment specific to it that we could not pin down. The effect is a
  # false-positive ERR_PNPM_LOCKFILE_CONFIG_MISMATCH on "overrides" that
  # aborts every Linux packaging build with `--frozen-lockfile`.
  #
  # Work around it by patching a writable copy of pnpm.cjs to self-heal
  # `wantedLockfile.overrides` from the current package.json overrides
  # whenever it comes back missing, right before pnpm's own consistency
  # check runs. This mirrors what pnpm's own code already does a few lines
  # later in the non-frozen-install path; we're just doing it earlier. A
  # genuine mismatch (lockfile has overrides that actually differ from
  # package.json) still throws normally, since this only fires when
  # `wantedLockfile.overrides` is `undefined`, not merely different.
  patchPnpmForOverridesBug = ''
    export PATH="${pkgs.nodejs_22}/bin:$PATH"
    PNPM_REAL=$(readlink -f "$(command -v pnpm)")
    PNPM_LIBEXEC=$(dirname "$(dirname "$PNPM_REAL")")
    WORKDIR=$(mktemp -d)
    cp -r "$PNPM_LIBEXEC" "$WORKDIR/pnpm"
    chmod -R u+w "$WORKDIR/pnpm"
    PATCHED_CJS="$WORKDIR/pnpm/dist/pnpm.cjs"
    sed -i "/createOverridesMapFromParsed)(opts.parsedOverrides)/a if (ctx.wantedLockfile.overrides === undefined) { if (overridesMap) { if (Object.keys(overridesMap).length > 0) { ctx.wantedLockfile.overrides = overridesMap; } } }" "$PATCHED_CJS"
    mkdir -p "$WORKDIR/bin"
    printf '#!/bin/sh\nexec node "%s" "$@"\n' "$PATCHED_CJS" > "$WORKDIR/bin/pnpm"
    chmod +x "$WORKDIR/bin/pnpm"
    export PATH="$WORKDIR/bin:$PATH"
  '';

  # Fetch and cache the pnpm offline store for reproducible installs.
  # pnpm_9 supports lockfile format 9.0 used by admin-ui/pnpm-lock.yaml.
  pnpmDeps = pkgs.pnpm_9.fetchDeps {
    pname = "cosmian-auth-admin-ui-deps";
    inherit version;

    src = lib.cleanSourceWith {
      src = ../admin-ui;
      filter = sourceFilter;
    };

    prePnpmInstall = patchPnpmForOverridesBug;

    hash =
      let
        platformSuffix =
          if stdenv.hostPlatform.isDarwin then
            "darwin"
          else if stdenv.hostPlatform.isx86_64 then
            "linux-x86_64"
          else if stdenv.hostPlatform.isAarch64 then
            "linux-aarch64"
          else
            builtins.throw "Unsupported platform for admin-ui pnpm hash: ${stdenv.hostPlatform.system}";
        hashFile = ./expected-hashes + "/admin-ui.pnpm." + platformSuffix + ".sha256";
      in
      if builtins.pathExists hashFile then
        let
          raw = builtins.readFile hashFile;
          trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
        in
        # Pass the hash through — if it is a placeholder, fetchDeps will fail
        # with "hash mismatch: got sha256-..." which is the standard bootstrap
        # mechanism for obtaining the correct hash.
        trimmed
      else
        builtins.throw ("Expected admin-ui pnpm deps hash file not found: " + hashFile);
  };

in
stdenv.mkDerivation {
  pname = "cosmian-auth-admin-ui";
  inherit version;

  src = lib.cleanSourceWith {
    src = ../admin-ui;
    filter = sourceFilter;
  };

  nativeBuildInputs = [
    pkgs.nodejs_22
    pkgs.pnpm_9
    pkgs.pnpm_9.configHook
  ];

  # configHook runs pnpm install --offline --frozen-lockfile
  inherit pnpmDeps;

  # Node.js 22.10.0 (pinned in nixpkgs) doesn't satisfy the engines requirement
  # of @rolldown/binding-linux-x64-gnu ("^20.19.0 || >=22.12.0"), so pnpm
  # silently skips that optional native binding.  The ABI is stable across all
  # Node 22.x releases (ABI 127), so the binary runs fine on 22.10.0.
  # Telling pnpm to evaluate engine constraints against 22.12.0 makes it
  # include the binding during the offline install step.
  #
  # Also apply the same wantedLockfile.overrides self-heal as pnpmDeps above
  # — this second `pnpm install` (run by configHook) goes through the same
  # frozen-lockfile consistency check and is exposed to the same bug.
  prePnpmInstall = ''
    export npm_config_node_version="22.12.0"
    ${patchPnpmForOverridesBug}
  '';

  # No native binaries — skip the strip/file-detection phase which requires
  # the `file` command. Without this, Nix's fixupPhase fails on modern nixpkgs
  # where `file` is not in the stdenv's default PATH.
  dontStrip = true;

  buildPhase = ''
    export HOME=$TMPDIR
    pnpm run build
  '';

  installPhase = ''
    if [ ! -d dist ]; then
      echo "ERROR: dist/ not found after pnpm run build" >&2
      exit 1
    fi
    if [ ! -f dist/index.html ]; then
      echo "ERROR: dist/index.html not found — Vite build may have failed" >&2
      exit 1
    fi
    mkdir -p $out/dist
    cp -r dist/. $out/dist/
    echo "admin-ui installed to $out/dist/ ($(find $out/dist -type f | wc -l) files)"
  '';

  meta = with lib; {
    description = "Cosmian Authentication Server — Admin UI";
    homepage = "https://github.com/Cosmian/authentication";
    platforms = platforms.unix;
  };
}
