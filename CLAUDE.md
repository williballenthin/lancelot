# Claude Code Memory

## Development Commands

**Always use the justfile for all operations. Never invoke cargo directly.**

Run `just` to see all available commands. Common operations:

```bash
just build          # Build debug (with cranelift for speed)
just build-release  # Build release
just check          # Fast compilation check
just lint           # Run all lints (check, clippy, fmt-check)
just fmt            # Format code
just test           # Run all tests
just test-rust      # Run Rust tests only (no Python)
just test-core      # Test lancelot-core only
just test-flirt     # Test lancelot-flirt only
just all            # Run lint + test (use before committing)
just clean          # Clean build artifacts
just warmup         # Populate rustc cache with various builds
```

## Version Bumps

Use the justfile recipe (or script directly) to ensure all locations are updated:

```bash
just bump-version <version>
# or: .github/workflows/bump-version.sh <version>
```

This updates versions in all Cargo.toml and pyproject.toml files, including dependency references.

## CI Workflows

### ci.yml
Runs on push/PR. Jobs: check, fmt (nightly), clippy (nightly), test for lancelot/lancelot-flirt, pytest for pylancelot/pyflirt (Python 3.14)

### python-wheels.yaml
Builds Python wheels. Triggers: release, manual (`workflow_dispatch`), or PR with "Full Build" label.
- Platforms: Linux (x86_64, aarch64, i686, armv7), macOS (x86_64, aarch64), Windows (x86_64, i686, aarch64)
- Python versions: 3.10-3.14, PyPy 3.11 (where supported)
- Publishes to PyPI on tagged releases

### publish-cargo.yaml
Publishes to crates.io on release. Order: flirt → core → bin (with 60s delays for propagation)
