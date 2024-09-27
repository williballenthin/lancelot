## testing

```console
$ pip install maturin[patchelf] pytest
$ maturin develop --release --extras dev
$ pytest
```

use `maturin develop --release` for fast builds.

## local builds

```console
$ maturin develop --release
$ ../target/wheels/*.whl
```
