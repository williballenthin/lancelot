## testing

```sh
# use a py3 virtual environment
$ pip install maturin[patchelf] pytest
$ maturin develop --release --extras dev
$ pytest
```

use `maturin develop --release` for fast builds.
