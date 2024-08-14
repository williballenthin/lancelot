# build with various profiles to populate the rustc cache
warmup:
    # build with cranelift
    -env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo build -Zcodegen-backend
    # build without cranelift (as hx will do)
    -cargo build
    # build in release profile
    -cargo build --release

    # build unicorn dep, which is only used in tests, and takes a while
    -cd core && env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo test -Zcodegen-backend
    -cd core && cargo test

check:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo check -Zcodegen-backend

clippy:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo clippy -Zcodegen-backend

fmt:
    cargo fmt

lint: check clippy fmt

test-core:
    cd core && \
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo test -Zcodegen-backend

test-flirt:
    cd flirt && \
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo test -Zcodegen-backend

test-pylancelot-rs:
    cd pylancelot && \
    cargo test  # can't use cranelift when linking to python

test-pylancelot-py:
    bash .github/scripts/pytest-pylancelot.sh

test-pylancelot: test-pylancelot-rs test-pylancelot-py

test-pyflirt-rs:
    cd pyflirt && \
    cargo test  # can't use cranelift when linking to python

test-pyflirt-py:
    bash .github/scripts/pytest-pyflirt.sh

test-pyflirt: test-pyflirt-rs test-pyflirt-py

test: test-core test-flirt test-pylancelot test-pyflirt

build:
    env CARGO_PROFILE_DEV_CODEGEN_BACKEND=cranelift cargo build -Zcodegen-backend

build-release:
    cargo build --release
