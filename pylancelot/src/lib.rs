use lancelot::loader::pe::PE as lPE;
use pyo3::{self, exceptions::Exception::ValueError, prelude::*, types::PyBytes, wrap_pyfunction};

#[pyclass]
struct PE {
    inner: lPE,
}

#[pyfunction]
fn from_bytes(buf: &PyBytes) -> PyResult<PE> {
    Ok(PE {
        inner: lPE::from_bytes(buf.as_bytes()).map_err(|e| ValueError::py_err(format!("{:#x?}", e)))?,
    })
}

#[pymodule]
fn pylancelot(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PE>()?;
    m.add_wrapped(wrap_pyfunction!(from_bytes))?;

    Ok(())
}
