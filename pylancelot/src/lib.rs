use pyo3::{self, prelude::*};

#[pyclass]
struct PE {
    inner: lancelot::loader::pe::PE,
}

#[pymodule]
fn pylancelot(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PE>()?;

    Ok(())
}
