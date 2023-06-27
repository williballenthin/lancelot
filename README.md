# Lancelot

[![CI Status](https://github.com/williballenthin/lancelot/workflows/CI/badge.svg)](https://github.com/williballenthin/lancelot/actions)

intel x86(-64) code analysis library that reconstructs control flow


## dependencies

  - make
  - cmake
  - pkg-config

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
$ pushd core; cargo test; popd
$ pushd flirt; cargo test; popd
$ pushd bin; cargo test; popd

$ pushd pylancelot
$   # install maturin if necessary
$   maturin develop --extras dev
$   pytest
$ popd

$ pushd pyflirt
$   # install maturin if necessary
$   maturin develop  --extras dev
$   pytest
$ popd
```
