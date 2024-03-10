# Lancelot

[![CI Status](https://github.com/williballenthin/lancelot/workflows/CI/badge.svg)](https://github.com/williballenthin/lancelot/actions)

intel x86(-64) code analysis library that reconstructs control flow


## dependencies

  - make
  - cmake
  - pkg-config

Consider using [cranelift](https://github.com/rust-lang/rustc_codegen_cranelift) during development:

```console
$ rustup component add rustc-codegen-cranelift-preview --toolchain nightly
$ set -x CARGO_PROFILE_DEV_CODEGEN_BACKEND cranelift
$ cargo build -Zcodegen-backend
```

Also consider using `mold`:

```console
$ mold -run cargo build
```

If it doesn't work with your (read: Willi's) nixOS setup,
use it just for incremental builds.

## maintenance

```
$ rustup update  # update rust compiler

$ cargo update  # update dependencies, not crossing major versions

$ cargo outdated -x unicorn  # find outdated major version dependencies
```

because we use an older version of unicorn thats easier to build with cargo,
we want to ignore any old dependencies stemming from unicorn.

## testing

```
$ pre-commit run --all-files --hook-stage manual
```
