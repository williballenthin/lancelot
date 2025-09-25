#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434
#![allow(clippy::useless_conversion)] // something to do with PyErr conversion, try to remove again eventually

use anyhow::Error;
use lancelot_flirt::{pat, sig};
use pyo3::{prelude::*, types::*, wrap_pyfunction};

/// ValueError -> "you're doing something wrong"
fn to_value_error(e: anyhow::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("{e}"))
}

fn to_py_err(e: Error) -> PyErr {
    match e.downcast_ref::<sig::SigError>() {
        Some(sig::SigError::NotSupported) => return to_value_error(e),
        Some(sig::SigError::CompressionNotSupported(_)) => return to_value_error(e),
        Some(sig::SigError::CorruptSigFile) => return to_value_error(e),
        None => (),
    };

    match e.downcast_ref::<pat::PatError>() {
        Some(pat::PatError::NotSupported) => return to_value_error(e),
        Some(pat::PatError::CorruptPatFile) => return to_value_error(e),
        None => (),
    };

    to_value_error(e)
}

// class FlirtSignature:
//   @property
//   names: Map[str, Tuple[str, int]] = {"__EH_prolog": ("public", 0x0)}
//
// parse_sig(bytes) -> [FlirtSignature]
// parse_pat(bytes) -> [FlirtSignature]
//
// compile([FlirtSignature]) -> FlirtMatcher
// FlirtMatcher.match(bytes) -> [FlirtSignature]

/// A FLIRT signature that can be used to match a sequence of bytes to function
/// name.
#[pyclass]
#[derive(Clone)]
pub struct FlirtSignature {
    inner: lancelot_flirt::FlirtSignature,
}

#[pymethods]
impl FlirtSignature {
    #[getter]
    pub fn names(&self, py: Python) -> Vec<Py<PyAny>> {
        self.inner
            .names
            .iter()
            .map(|name| {
                let (name, ty, offset) = match name {
                    lancelot_flirt::Symbol::Public(name) => {
                        (String::from(&name.name), String::from("public"), name.offset)
                    }
                    lancelot_flirt::Symbol::Local(name) => {
                        (String::from(&name.name), String::from("local"), name.offset)
                    }
                    lancelot_flirt::Symbol::Reference(name) => {
                        (String::from(&name.name), String::from("reference"), name.offset)
                    }
                };

                let data = [
                    name.into_pyobject(py).unwrap().into_any().unbind(),
                    ty.into_pyobject(py).unwrap().into_any().unbind(),
                    offset.into_pyobject(py).unwrap().into_any().unbind(),
                ];

                PyTuple::new(py, data.iter()).unwrap().into_any().unbind()
            })
            .collect()
    }

    fn __str__(&self) -> PyResult<String> {
        use lancelot_flirt::Symbol;
        if let Some(Symbol::Public(name)) = self.inner.names.iter().find(|name| matches!(name, Symbol::Public(_))) {
            Ok(format!("FlirtSignature(\"{}\")", name.name))
        } else {
            Ok(String::from("FlirtSignature(<unknown public name>)"))
        }
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }
}

#[pyfunction]
pub fn parse_sig(buf: &Bound<'_, PyBytes>) -> PyResult<Vec<FlirtSignature>> {
    Ok(sig::parse(buf.as_bytes())
        .map_err(to_py_err)?
        .into_iter()
        .map(|sig| FlirtSignature { inner: sig })
        .collect())
}

#[pyfunction]
pub fn parse_pat(s: String) -> PyResult<Vec<FlirtSignature>> {
    Ok(pat::parse(&s)
        .map_err(to_py_err)?
        .into_iter()
        .map(|sig| FlirtSignature { inner: sig })
        .collect())
}

#[pyclass]
pub struct FlirtMatcher {
    inner: lancelot_flirt::FlirtSignatureSet,
}

#[pymethods]
impl FlirtMatcher {
    pub fn r#match(&self, buf: &Bound<'_, PyBytes>) -> Vec<FlirtSignature> {
        self.inner
            .r#match(buf.as_bytes())
            .into_iter()
            .map(|sig| FlirtSignature { inner: sig.clone() })
            .collect()
    }
}

#[pyfunction]
pub fn compile(_py: Python, sigs: &Bound<'_, PyList>) -> PyResult<FlirtMatcher> {
    let sigs = match sigs.extract::<Vec<FlirtSignature>>() {
        Err(_) => {
            return Err(pyo3::exceptions::PyValueError::new_err(String::from(
                "must pass only `FlirtSignature` instances to `compile`",
            )))
        }
        Ok(sigs) => sigs,
    };

    Ok(FlirtMatcher {
        inner: lancelot_flirt::FlirtSignatureSet::with_signatures(sigs.into_iter().map(|sig| sig.inner).collect()),
    })
}

#[pymodule]
fn flirt(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_pat, m)?)?;
    m.add_function(wrap_pyfunction!(parse_sig, m)?)?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_class::<FlirtSignature>()?;
    m.add_class::<FlirtMatcher>()?;

    Ok(())
}
