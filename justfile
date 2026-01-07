# lancelot justfile - run `just` or `just help` to see available commands

# Default recipe - show help
default: help

# Show available commands
help:
    @echo "lancelot build system"
    @echo ""
    @echo "Usage: just <recipe>"
    @echo ""
    @echo "Common recipes:"
    @echo "  build          - Build the project (stable toolchain)"
    @echo "  build-release  - Build with optimizations"
    @echo "  test           - Run all tests"
    @echo "  lint           - Run all lints (check, clippy, fmt)"
    @echo "  ci             - Run full CI pipeline (lint + test)"
    @echo ""
    @echo "Individual lint recipes:"
    @echo "  check          - Run cargo check"
    @echo "  clippy         - Run clippy lints"
    @echo "  fmt            - Run rustfmt"
    @echo "  fmt-check      - Check formatting without modifying"
    @echo ""
    @echo "Individual test recipes:"
    @echo "  test-core      - Test lancelot core library"
    @echo "  test-flirt     - Test lancelot-flirt library"
    @echo "  test-pylancelot - Test pylancelot (Rust + Python)"
    @echo "  test-pyflirt   - Test pyflirt (Rust + Python)"
    @echo ""
    @echo "Development recipes (uses cranelift for faster builds, requires nightly):"
    @echo "  dev-build      - Fast build with cranelift"
    @echo "  dev-check      - Fast check with cranelift"
    @echo "  warmup         - Populate rustc cache with various profiles"

# ============================================================================
# Main build recipes
# ============================================================================

# Build the project (stable toolchain)
build:
    cargo build

# Build with optimizations
build-release:
    cargo build --release

# ============================================================================
# Lint recipes (matches CI workflow)
# ============================================================================

# Run cargo check
check:
    cargo check

# Run clippy with warnings as errors (requires nightly)
clippy:
    cargo +nightly clippy -- -D warnings

# Format code with rustfmt (requires nightly for all features)
fmt:
    cargo +nightly fmt --all

# Check formatting without modifying files
fmt-check:
    cargo +nightly fmt --all -- --check

# Run all lints: check, clippy, and format check
lint: check clippy fmt-check

# ============================================================================
# Test recipes (matches CI workflow)
# ============================================================================

# Run all tests
test: test-core test-flirt test-pylancelot test-pyflirt

# Test lancelot core library
test-core:
    cargo test -p lancelot

# Test lancelot-flirt library
test-flirt:
    cargo test -p lancelot-flirt

# Test pylancelot Rust code
test-pylancelot-rs:
    cd pylancelot && cargo test

# Test pylancelot Python code
test-pylancelot-py:
    bash .github/scripts/pytest-pylancelot.sh

# Test pylancelot (both Rust and Python)
test-pylancelot: test-pylancelot-rs test-pylancelot-py

# Test pyflirt Rust code
test-pyflirt-rs:
    cd pyflirt && cargo test

# Test pyflirt Python code
test-pyflirt-py:
    bash .github/scripts/pytest-pyflirt.sh

# Test pyflirt (both Rust and Python)
test-pyflirt: test-pyflirt-rs test-pyflirt-py

# ============================================================================
# CI recipe - run the full pipeline
# ============================================================================

# Run full CI pipeline (matches GitHub Actions workflow)
ci: lint test

# ============================================================================
# Development recipes (optional - uses cranelift for faster builds)
# ============================================================================

# Fast build with cranelift (requires nightly)
dev-build:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly build -Zcodegen-backend

# Fast check with cranelift (requires nightly)
dev-check:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly check -Zcodegen-backend

# Fast clippy with cranelift (requires nightly)
dev-clippy:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly clippy -Zcodegen-backend

# Build with various profiles to populate the rustc cache
warmup:
    # build with cranelift
    -env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly build -Zcodegen-backend
    # build without cranelift (as hx will do)
    -cargo build
    # build in release profile
    -cargo build --release
    # build unicorn dep, which is only used in tests, and takes a while
    -cd core && env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly test -Zcodegen-backend
    -cd core && cargo test
