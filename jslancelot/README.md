# Javascript bindings for Lancelot

## prerequisites

  - [wasm-pack](https://rustwasm.github.io/wasm-pack/)
  - [zig](https://ziglang.org/download/), v0.8.1 is known to work

## build

First, update the path to `zig` in `zcc`:

```sh
#!/bin/sh

/home/user/.bin/zig-linux-x86_64-0.8.1/zig cc -target wasm32-wasi $@
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ here
```

Then invoke `wasm-pack`:

```
CC="$(readlink -f zcc)" CXX="$(readlink -f zcc)" wasm-pack build --release --target web
```
