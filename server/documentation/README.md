# TL;DR

The main documentation of the Authentication Verifier is in
[docs/index.md](./docs/index.md).

## Rendering the documentation

This documentation is built with [mdBook](https://rust-lang.github.io/mdBook/).

Install the toolchain:

```sh
cargo install mdbook --version 0.4.52 --locked
cargo install mdbook-admonish --version 1.20.0
cargo install mdbook-mermaid --version 0.16.0
```

The book source lives in `docs/`. To render this module standalone:

```sh
git submodule update --init theme
mdbook serve     # live preview; static output is written to book/
```

The pages are also aggregated into the combined Cosmian documentation by the
`public_documentation` repository.
