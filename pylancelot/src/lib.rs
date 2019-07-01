use pyo3;
use pyo3::types::{PyBytes};
use pyo3::prelude::*;

use lancelot::workspace;


#[pymodule]
fn pylancelot(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "from_bytes")]
    /// from_bytes(filename, buf, /)
    /// --
    ///
    /// Create a workspace from the given bytes.
    ///
    /// Args:
    ///   filename (str): the source filename
    ///   buf (bytes): the bytes containing a PE, shellcode, etc.
    ///
    /// Raises:
    ///   ValueError: if failed to create the workspace. TODO: more specific.
    ///
    fn from_bytes(_py: Python, filename: String, buf: &PyBytes) -> PyResult<PyWorkspace> {
        let ws = match workspace::Workspace::from_bytes(&filename, buf.as_bytes()).load() {
            Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to create workspace")),
            Ok(ws) => ws,
        };
        Ok(PyWorkspace{ws})
    }

    #[pyclass]
    pub struct PyWorkspace {
        ws: workspace::Workspace
    }

    #[pymethods]
    impl PyWorkspace {
        #[getter]
        /// filename(self, /)
        /// --
        ///
        /// Fetch the filename.
        ///
        /// ```python
        /// import pylancelot
        /// ws = pylancelot.from_bytes('foo.bin', b'\xEB\xFE')
        /// assert ws.filename == 'foo.bin'
        /// ```
        pub fn filename(&self) -> PyResult<String> {
            Ok(self.ws.filename.clone())
        }
    }

    Ok(())
}


