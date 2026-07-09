# Claude Code Memory

## Version Bumps

Use the version bump script to ensure all locations are updated:

```bash
.github/workflows/bump-version.sh <version>
```

This updates versions in all Cargo.toml, pyproject.toml, and package.json files, including dependency references.

## CI Workflows

### ci.yml
Runs on push/PR. Jobs:
- `cargo check`, `cargo fmt` (nightly), `cargo clippy` (nightly)
- `cargo test` for lancelot and lancelot-flirt
- pytest for pylancelot and pyflirt (Python 3.14)
- wasm: `cargo build -p lancelot --target wasm32-unknown-unknown` using clang and `wasm32-toolchain.cmake`, then builds jslancelot and runs its Node tests

## jslancelot

JavaScript bindings for npm at `jslancelot/`, mirroring pylancelot's API (bytes in, BinExport2 bytes out) but running the wasm build of the core library, so the same package works in both Node and the browser. `just build` in `jslancelot/` compiles the crate to wasm32-unknown-unknown and generates the JS glue with wasm-bindgen (the wasm-bindgen-cli version must match the `wasm-bindgen` pin in `jslancelot/Cargo.toml`).

### python-wheels.yaml
Builds Python wheels. Triggers: release, manual (`workflow_dispatch`), or PR with "Full Build" label.
- Platforms: Linux (x86_64, aarch64, i686, armv7), macOS (x86_64, aarch64), Windows (x86_64, i686, aarch64)
- Python versions: 3.10-3.14, PyPy 3.11 (where supported)
- Publishes to PyPI on tagged releases

### npm-package.yaml
Builds the jslancelot npm package (wasm + `npm pack`). Triggers: release, manual (`workflow_dispatch`).
- Runs the Node tests, uploads the .tgz as a workflow artifact, and attaches it to the release when triggered by one
- Does NOT publish to npm; to release manually: `npm publish jslancelot-<version>.tgz`

### publish-cargo.yaml
Publishes to crates.io on release. Order: flirt → core → bin (with 60s delays for propagation)
