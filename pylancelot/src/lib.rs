#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434
#![allow(clippy::useless_conversion)] // something to do with PyErr conversion, try to remove again eventually

use ::lancelot::{
    loader::{coff::COFFError, pe::PEError},
    module::ModuleError,
    pagemap::PageMapError,
    util::UtilError,
    workspace::{
        config::{Configuration, DynamicConfiguration},
        export::binexport2::export_workspace_to_binexport2,
        WorkspaceError,
    },
};
use anyhow::Error;
use pyo3::{prelude::*, types::*, wrap_pyfunction};
use std::path::PathBuf;

/// ValueError -> "you're doing something wrong"
fn to_value_error(e: anyhow::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("{e}"))
}

fn to_py_err(e: Error) -> PyErr {
    #[allow(clippy::single_match)]
    match e.downcast_ref::<WorkspaceError>() {
        Some(WorkspaceError::BufferTooSmall) => return to_value_error(e),
        Some(WorkspaceError::FormatNotSupported { source: _ }) => return to_value_error(e),
        None => (),
    };

    match e.downcast_ref::<PEError>() {
        Some(PEError::FormatNotSupported(_)) => return to_value_error(e),
        Some(PEError::MalformedPEFile(_)) => return to_value_error(e),
        None => (),
    };

    match e.downcast_ref::<COFFError>() {
        Some(COFFError::FormatNotSupported(_)) => return to_value_error(e),
        Some(COFFError::MalformedCOFFFile(_)) => return to_value_error(e),
        None => (),
    };

    #[allow(clippy::single_match)]
    match e.downcast_ref::<ModuleError>() {
        Some(ModuleError::InvalidAddress(_)) => return to_value_error(e),
        None => (),
    };

    match e.downcast_ref::<UtilError>() {
        Some(UtilError::FileAccess) => return to_value_error(e),
        Some(UtilError::FileFormat) => return to_value_error(e),
        None => (),
    };

    #[allow(clippy::single_match)]
    match e.downcast_ref::<PageMapError>() {
        Some(PageMapError::NotMapped) => return to_value_error(e),
        None => (),
    };

    to_value_error(e)
}

/// analyze the given bytes with Lancelot and emit a BinExport2 protobuf.
///
/// Args:
///   buf (bytes): the raw bytes of a supported file (e.g., PE or COFF)
///   executable_id (Optional[str]): name of the file, if known
///   sig_paths (Optional[list[str]]): paths to FLIRT signature files
///   function_hints (Optional[list[int]]): known function virtual addresses
///
/// Returns: bytes
#[pyfunction]
#[pyo3(signature = (buf, executable_id=None, sig_paths=None, function_hints=None))]
pub fn binexport2_from_bytes(
    py: Python,
    buf: &Bound<'_, PyBytes>,
    executable_id: Option<String>,
    sig_paths: Option<Vec<String>>,
    function_hints: Option<Vec<u64>>,
) -> PyResult<Py<PyBytes>> {
    let mut config: DynamicConfiguration = Default::default();
    if let Some(sig_paths) = sig_paths {
        let sig_paths: Vec<_> = sig_paths.iter().map(PathBuf::from).collect();
        config = config.with_sig_paths(&sig_paths);
    }

    if let Some(function_hints) = function_hints {
        config = config.with_function_hints(&function_hints);
    }

    let config = config.clone();

    let ws = ::lancelot::workspace::workspace_from_bytes(config, buf.as_bytes()).map_err(to_py_err)?;
    let hash = sha256::digest(buf.as_bytes());
    export_workspace_to_binexport2(&*ws, hash, executable_id)
        .map(|buf| PyBytes::new(py, &buf).unbind())
        .map_err(to_py_err)
}

#[pymodule(name = "_lib")]
fn lancelot(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();

    // note that these are re-exported by:
    // pylancelot/python/lancelot/__init__.py
    m.add_function(wrap_pyfunction!(binexport2_from_bytes, m)?)?;

    Ok(())
}
