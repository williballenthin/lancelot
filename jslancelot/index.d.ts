export interface AnalysisOptions {
  /** name of the file, if known */
  executableId?: string;
  /** contents of FLIRT signature files (.sig or .pat, recognized by magic) */
  sigs?: Array<Uint8Array | ArrayBuffer>;
  /** known function virtual addresses */
  functionHints?: Array<number | bigint>;
}

/**
 * initialize the WebAssembly module.
 *
 * this happens automatically on the first analysis call,
 * but can be invoked explicitly to control where the .wasm bytes come from,
 * e.g., when a bundler relocates assets.
 */
export function init(
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
): Promise<void>;

/**
 * analyze the given bytes with Lancelot and emit a BinExport2 protobuf.
 *
 * @param buf the raw bytes of a supported file (e.g., PE or COFF)
 * @returns the BinExport2-encoded protobuf bytes
 */
export function getBinExport2BytesFromBytes(
  buf: Uint8Array | ArrayBuffer,
  options?: AnalysisOptions,
): Promise<Uint8Array>;
