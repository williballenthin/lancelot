# Default recipe: list available commands
default:
    @just --list

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

# Run cargo check (fast compilation check)
check:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly check -Zcodegen-backend

# Run clippy linter
clippy:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly clippy -Zcodegen-backend

# Format code with rustfmt
fmt:
    cargo +nightly fmt

# Check formatting without modifying files
fmt-check:
    cargo +nightly fmt --check

# Run all lints (check, clippy, fmt-check)
lint: check clippy fmt-check

# Test lancelot-core
test-core:
    cd core && \
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly test -Zcodegen-backend

# Test lancelot-flirt
test-flirt:
    cd flirt && \
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly test -Zcodegen-backend

# Test pylancelot Rust code
test-pylancelot-rs:
    cd pylancelot && \
    cargo test  # can't use cranelift when linking to python

# Test pylancelot Python code
test-pylancelot-py:
    bash .github/scripts/pytest-pylancelot.sh

# Test pylancelot (Rust + Python)
test-pylancelot: test-pylancelot-rs test-pylancelot-py

# Test pyflirt Rust code
test-pyflirt-rs:
    cd pyflirt && \
    cargo test  # can't use cranelift when linking to python

# Test pyflirt Python code
test-pyflirt-py:
    bash .github/scripts/pytest-pyflirt.sh

# Test pyflirt (Rust + Python)
test-pyflirt: test-pyflirt-rs test-pyflirt-py

# Run all tests
test: test-core test-flirt test-pylancelot test-pyflirt

# Run all Rust tests only (no Python)
test-rust: test-core test-flirt test-pylancelot-rs test-pyflirt-rs

# Build debug (with cranelift for speed)
build:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo +nightly build -Zcodegen-backend

# Build release
build-release:
    cargo build --release

# Clean build artifacts
clean:
    cargo clean

# Run all checks (lint + test) - use before committing
all: lint test

# Bump version across all crates (usage: just bump-version 1.2.3)
bump-version version:
    .github/workflows/bump-version.sh {{version}}
