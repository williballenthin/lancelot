# Claude Code Memory

## Version Bumps

Use the version bump script to ensure all locations are updated:

```bash
.github/workflows/bump-version.sh <version>
```

This updates versions in all Cargo.toml and pyproject.toml files, including dependency references.

## CI Workflows

### ci.yml
Runs on push/PR. Jobs:
- `cargo check`, `cargo fmt` (nightly), `cargo clippy` (nightly)
- `cargo test` for lancelot and lancelot-flirt
- pytest for pylancelot and pyflirt (Python 3.14)

### python-wheels.yaml
Builds Python wheels. Triggers: release, manual (`workflow_dispatch`), or PR with "Full Build" label.
- Platforms: Linux (x86_64, aarch64, i686, armv7), macOS (x86_64, aarch64), Windows (x86_64, i686, aarch64)
- Python versions: 3.10-3.14, PyPy 3.11 (where supported)
- Publishes to PyPI on tagged releases

### publish-cargo.yaml
Publishes to crates.io on release. Order: flirt → core → bin (with 60s delays for propagation)
