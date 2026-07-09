# jslancelot

JavaScript bindings for [lancelot](https://github.com/williballenthin/lancelot),
a binary analysis framework for x32/x64 PE (and COFF) files.

the API surface is intentionally tiny, mirroring
[pylancelot](https://github.com/williballenthin/lancelot/tree/master/pylancelot):
you provide the bytes of an input file, and lancelot produces a
[BinExport2](https://github.com/google/binexport)-encoded protobuf that
describes the complete analysis — instructions, basic blocks, functions,
control flow, call graph, etc. — which you can then process with other logic.

unlike pylancelot, which links against a native library, jslancelot runs
lancelot compiled to WebAssembly. there are no native dependencies, and the
same package works in Node and entirely within the browser.

## usage

```js
import { getBinExport2BytesFromBytes } from "jslancelot";

// Node:
import { readFile } from "node:fs/promises";
const buf = await readFile("kernel32.dll");

// or in the browser, e.g., from a file input:
// const buf = new Uint8Array(await file.arrayBuffer());

const be2 = await getBinExport2BytesFromBytes(buf);
// be2 is a Uint8Array containing a BinExport2 protobuf
```

optionally provide analysis inputs:

```js
const be2 = await getBinExport2BytesFromBytes(buf, {
  // name of the file, recorded in the BinExport2 metadata
  executableId: "kernel32.dll",

  // contents of FLIRT signature files used to recognize known code.
  // both compiled (.sig) and textual (.pat) formats are supported,
  // recognized by content. note: file *contents*, not paths,
  // since there is no filesystem in the browser.
  sigs: [await readFile("libcmt_15_msvc_x86.sig")],

  // virtual addresses known to be functions
  functionHints: [0x7dd70e02n],
});
```

### decoding the BinExport2

the BinExport2 protobuf schema ships with this package, so you can decode the
results with your protobuf library of choice, such as
[protobufjs](https://www.npmjs.com/package/protobufjs):

```js
import protobuf from "protobufjs";

const root = await protobuf.load(
  new URL(import.meta.resolve("jslancelot/binexport2.proto")).pathname);
const BinExport2 = root.lookupType("BinExport2");
const be2 = BinExport2.decode(await getBinExport2BytesFromBytes(buf));

console.log(`instructions: ${be2.instruction.length}`);
```

### loading the wasm module

the WebAssembly module (~2.3MB) is loaded and compiled on the first call.
this happens automatically: from disk in Node, via `fetch()` relative to the
module URL in the browser. if your bundler relocates assets, initialize
explicitly:

```js
import { init } from "jslancelot";

await init(fetch("/assets/jslancelot_bg.wasm"));
```

## building

```console
$ rustup target add wasm32-unknown-unknown
$ cargo install wasm-bindgen-cli --version 0.2.100 --locked
$ npm run build   # runs build.sh: cargo build + wasm-bindgen
$ npm test        # requires Node >= 18
```

cross-compiling the bundled Zydis C library requires clang and cmake;
see the "WebAssembly" section of the top-level README.
