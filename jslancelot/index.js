import initWasm, { binexport2_from_bytes } from "./wasm/jslancelot.js";

let ready = null;

/// initialize the WebAssembly module.
///
/// this happens automatically on the first analysis call,
/// but can be invoked explicitly to control where the .wasm bytes come from,
/// e.g., when a bundler relocates assets:
///
///     await init(fetch("/assets/jslancelot_bg.wasm"));
///
/// accepts anything that wasm-bindgen's init accepts:
/// a URL, Request, Response, BufferSource, or WebAssembly.Module.
export function init(input) {
  if (ready === null) {
    ready = (async () => {
      if (input === undefined && typeof process !== "undefined" && process.versions?.node) {
        // Node can't fetch() the file: URL that wasm-bindgen defaults to,
        // so read the module from disk instead.
        const { readFile } = await import("node:fs/promises");
        input = await readFile(new URL("./wasm/jslancelot_bg.wasm", import.meta.url));
      }
      await initWasm(input === undefined ? undefined : { module_or_path: input });
    })();
  }
  return ready;
}

function asUint8Array(buf) {
  if (buf instanceof Uint8Array) {
    return buf;
  }
  if (buf instanceof ArrayBuffer) {
    return new Uint8Array(buf);
  }
  throw new TypeError("buf must be a Uint8Array or ArrayBuffer");
}

/// analyze the given bytes with Lancelot and emit a BinExport2 protobuf.
///
/// options:
///   executableId (string): name of the file, if known
///   sigs (Uint8Array[]): contents of FLIRT signature files (.sig or .pat)
///   functionHints ((number|bigint)[]): known function virtual addresses
export async function getBinExport2BytesFromBytes(buf, options = {}) {
  await init();

  const { executableId, sigs, functionHints } = options;

  return binexport2_from_bytes(
    asUint8Array(buf),
    executableId,
    sigs === undefined ? undefined : sigs.map(asUint8Array),
    functionHints === undefined ? undefined : BigUint64Array.from(functionHints, BigInt),
  );
}
