# Lancelot

[![CI Status](https://github.com/williballenthin/lancelot/workflows/CI/badge.svg)](https://github.com/williballenthin/lancelot/actions)

intel x86(-64) code analysis library that reconstructs control flow


## testing

```
$ pushd core; cargo test; popd
$ pushd flirt; cargo test; popd

$ pushd pylancelot
$   maturin develop
$   pytest
$ popd
```