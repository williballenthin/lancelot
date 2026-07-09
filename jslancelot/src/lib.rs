#![allow(clippy::upper_case_acronyms)]

use ::lancelot::{
    workspace::{config::Configuration, export::binexport2::export_workspace_to_binexport2, workspace_from_bytes},
    VA,
};
use anyhow::Result;
use lancelot_flirt::{FlirtSignature, FlirtSignatureSet};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// configuration backed entirely by in-memory data,
/// since there's no filesystem to read from within a wasm sandbox.
struct StaticConfiguration {
    sigs:           Vec<FlirtSignature>,
    function_hints: Vec<VA>,
}

impl Configuration for StaticConfiguration {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        Ok(FlirtSignatureSet::with_signatures(self.sigs.clone()))
    }

    fn get_function_hints(&self) -> Result<Vec<VA>> {
        Ok(self.function_hints.clone())
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(StaticConfiguration {
            sigs:           self.sigs.clone(),
            function_hints: self.function_hints.clone(),
        })
    }
}

/// parse the contents of a FLIRT signature file,
/// which is either a compiled .sig file (recognized by its IDASGN magic)
/// or a textual .pat file.
fn parse_sig_buf(buf: &[u8]) -> Result<Vec<FlirtSignature>> {
    if buf.starts_with(b"IDASGN") {
        lancelot_flirt::sig::parse(buf)
    } else {
        lancelot_flirt::pat::parse(&String::from_utf8(buf.to_vec())?)
    }
}

fn to_js_error(e: anyhow::Error) -> JsError {
    JsError::new(&format!("{e}"))
}

/// analyze the given bytes with Lancelot and emit a BinExport2 protobuf.
///
/// Args:
///   buf: the raw bytes of a supported file (e.g., PE or COFF)
///   executable_id: name of the file, if known
///   sigs: contents of FLIRT signature files (.sig or .pat, sniffed by magic)
///   function_hints: known function virtual addresses
///
/// Returns: the BinExport2-encoded protobuf bytes
#[wasm_bindgen]
pub fn binexport2_from_bytes(
    buf: &[u8],
    executable_id: Option<String>,
    sigs: Option<Vec<js_sys::Uint8Array>>,
    function_hints: Option<Vec<u64>>,
) -> Result<Vec<u8>, JsError> {
    let mut config = StaticConfiguration {
        sigs:           Default::default(),
        function_hints: function_hints.unwrap_or_default(),
    };

    for sig_buf in sigs.unwrap_or_default() {
        config
            .sigs
            .extend(parse_sig_buf(&sig_buf.to_vec()).map_err(to_js_error)?);
    }

    let ws = workspace_from_bytes(Box::new(config), buf).map_err(to_js_error)?;

    let mut hasher = Sha256::new();
    hasher.update(buf);
    let hash = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>();

    export_workspace_to_binexport2(&*ws, hash, executable_id).map_err(to_js_error)
}
