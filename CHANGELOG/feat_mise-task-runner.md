## Features

- Add a `mise` task runner (`mise.toml`, `.mise/lib/common.sh`, `.mise/tasks/**`) as a thin, discoverable wrapper over the existing `.github/scripts/nix.sh`-driven test/package/docker/hash-update commands, plus `ui:*` tasks wrapping the admin-ui `pnpm` scripts; `mise.toml` pins the admin-ui Node/pnpm toolchain while Rust stays pinned in `rust-toolchain.toml` and Nix remains the build engine.

## CI

- Install `mise` via `jdx/mise-action@v2` in `packaging-docker.yml`, `packaging.yml`, and `packaging-tests.yml`, and replace the four script-by-path invocations (`nix.sh docker --load`, `test_docker_image.sh`, `nix.sh --link … package`, `verify_running_ui.sh`) with the equivalent `mise run …` commands so local and CI invocations match.
- Pin `jdx/mise-action@v2` to mise `2026.9.2` in all three packaging workflows so the action stops resolving the advertised `2026.9.3` VERSION whose release binaries are not published yet, fixing the `curl: (22) 404` failure in the `Install mise` step.

## Docs

- Document the `mise run …` shortcuts alongside the existing `cargo`/Nix commands in `AGENTS.md`, `.github/copilot-instructions.md`, and `admin-ui/DEV_GUIDE.md`.
