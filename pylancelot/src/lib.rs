use pyo3;
use pyo3::types::{PyBytes};
use pyo3::prelude::*;
use failure::{Error};

use lancelot::workspace;
use lancelot::arch::{RVA};



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

    #[pyclass]
    pub struct PySection {
        #[pyo3(get)]
        pub addr: i64,
        #[pyo3(get)]
        pub length: u64,
        #[pyo3(get)]
        pub perms: u8,
        #[pyo3(get)]
        pub name: String,
    }


    m.add("PERM_NONE", lancelot::loader::Permissions::empty().bits())?;
    m.add("PERM_R", lancelot::loader::Permissions::R.bits())?;
    m.add("PERM_W", lancelot::loader::Permissions::W.bits())?;
    m.add("PERM_X", lancelot::loader::Permissions::X.bits())?;
    m.add("PERM_RW", lancelot::loader::Permissions::RW.bits())?;
    m.add("PERM_RX", lancelot::loader::Permissions::RX.bits())?;
    m.add("PERM_RWX", lancelot::loader::Permissions::RWX.bits())?;

    #[pyclass]
    pub struct PyXref {
        pub src: i64,
        pub dst: i64,
        /// one of XREF_* constants
        pub typ: u8,
    }

    // keep in sync with pylancelot::PyWorkspace::translate_xref
    m.add("XREF_FALLTHROUGH", 1)?;
    m.add("XREF_CALL", 2)?;
    m.add("XREF_UNCONDITIONAL_JUMP", 3)?;
    m.add("XREF_CONDITIONAL_JUMP", 4)?;
    m.add("XREF_CONDITIONAL_MOVE", 5)?;

    #[pymethods]
    impl PyWorkspace {
        #[getter]
        /// filename(self, /)
        /// --
        ///
        /// Fetch the filename.
        /// ```
        pub fn filename(&self) -> PyResult<String> {
            Ok(self.ws.filename.clone())
        }

        #[getter]
        /// loader(self, /)
        /// --
        ///
        /// Fetch the name of the loader used to create the workspace.
        pub fn loader(&self) -> PyResult<String> {
            Ok(self.ws.loader.get_name())
        }

        #[getter]
        /// base_address(self, /)
        /// --
        ///
        /// Fetch the base address to which the module was loaded.
        pub fn base_address(&self) -> PyResult<u64> {
            Ok(self.ws.module.base_address.into())
        }

        #[getter]
        pub fn sections(&self) -> PyResult<Vec<PySection>> {
            Ok(self.ws.module.sections.iter()
                .map(|section| PySection{
                    addr: section.addr.into(),
                    length: section.buf.len() as u64,
                    perms: section.perms.bits(),
                    name: section.name.clone(),
                })
                .collect())
        }

        #[getter]
        pub fn functions(&self) -> PyResult<Vec<i64>> {
            Ok(self.ws.get_functions().map(|&rva| rva.into()).collect())
        }

        pub fn get_xrefs_from(&self, rva: i64) -> PyResult<Vec<PyXref>> {
            Ok(match self.ws.analysis.flow.xrefs.from.get(&RVA::from(rva)) {
                Some(xrefs) => {
                    xrefs.iter().map(|x| PyWorkspace::translate_xref(x)).collect()
                },
                None => vec![],
            })
        }

        pub fn get_xrefs_to(&self, rva: i64) -> PyResult<Vec<PyXref>> {
            Ok(match self.ws.analysis.flow.xrefs.to.get(&RVA::from(rva)) {
                Some(xrefs) => {
                    xrefs.iter().map(|x| PyWorkspace::translate_xref(x)).collect()
                },
                None => vec![],
            })
        }

        /// probe(self, rva, length=1, /)
        /// --
        ///
        /// Is the given address mapped?
        pub fn probe(&self, rva: i64, length: Option<usize>) -> PyResult<bool> {
            match length {
                Some(length) => Ok(self.ws.probe(RVA::from(rva), length)),
                None =>  Ok(self.ws.probe(RVA::from(rva), 1)),
            }
        }

        /// read_bytes(self, rva, length, /)
        /// --
        ///
        /// Read bytes from the given memory address.
        ///
        /// raises:
        ///   - LookupError: if the address is not mapped, or the length overruns.
        pub fn read_bytes<'p>(&self, py: Python<'p>, rva: i64, length: usize) -> PyResult<&'p pyo3::types::PyBytes> {
            match self.ws.read_bytes(RVA::from(rva), length) {
                Ok(buf) => Ok(pyo3::types::PyBytes::new(py, buf)),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_u8(self, rva, /)
        /// --
        ///
        pub fn read_u8(&self, rva: i64) -> PyResult<u8> {
            match self.ws.read_u8(RVA::from(rva)) {
                Ok(b) => Ok(b),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_u16(self, rva, /)
        /// --
        ///
        pub fn read_u16(&self, rva: i64) -> PyResult<u16> {
            match self.ws.read_u16(RVA::from(rva)) {
                Ok(b) => Ok(b),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_u32(self, rva, /)
        /// --
        ///
        pub fn read_u32(&self, rva: i64) -> PyResult<u32> {
            match self.ws.read_u32(RVA::from(rva)) {
                Ok(b) => Ok(b),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_u64(self, rva, /)
        /// --
        ///
        pub fn read_u64(&self, rva: i64) -> PyResult<u64> {
            match self.ws.read_u64(RVA::from(rva)) {
                Ok(b) => Ok(b),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_rva(self, rva, /)
        /// --
        ///
        /// Read the integer relative virtual address at the given address.
        /// The size of the RVA is dependent upon the bitness of the current workspace.
        pub fn read_rva(&self, rva: i64) -> PyResult<i64> {
            match self.ws.read_rva(RVA::from(rva)) {
                Ok(b) => Ok(b.into()),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }

        /// read_va(self, rva, /)
        /// --
        ///
        /// Read the integer virtual address at the given address.
        /// The size of the VA is dependent upon the bitness of the current workspace.
        pub fn read_va(&self, rva: i64) -> PyResult<u64> {
            match self.ws.read_va(RVA::from(rva)) {
                Ok(b) => Ok(b.into()),
                Err(e) => Err(PyWorkspace::translate_buffer_error(e)),
            }
        }
    }

    impl PyWorkspace {
        /// translate from a failure::Error returned by a Workspace
        /// while reading an element from memory into a pyo3/Python error
        /// corresponding to out-of-bounds-access.
        fn translate_buffer_error(e: Error) -> PyErr {
            match e.downcast::<lancelot::workspace::WorkspaceError>() {
                // we have to use the documentation for the associated routine,
                // such as `read_u8`, to determine what to inspect here.
                Ok(lancelot::workspace::WorkspaceError::InvalidAddress) => {
                    pyo3::exceptions::LookupError::py_err("invalid address")
                },
                Ok(lancelot::workspace::WorkspaceError::BufferOverrun) => {
                    pyo3::exceptions::LookupError::py_err("buffer overrun")
                }
                Ok(_) => {
                    // this should never be hit
                    pyo3::exceptions::RuntimeError::py_err("unexpected error")
                },
                Err(_) => {
                    // this should never be hit
                    pyo3::exceptions::RuntimeError::py_err("unexpected error")
                },
            }
        }

        fn translate_xref(x: &lancelot::xref::Xref) -> PyXref {
            PyXref {
                src: x.src.into(),
                dst: x.dst.into(),
                typ: match x.typ {
                    lancelot::xref::XrefType::Fallthrough => 1,
                    lancelot::xref::XrefType::Call => 2,
                    lancelot::xref::XrefType::UnconditionalJump => 3,
                    lancelot::xref::XrefType::ConditionalJump => 4,
                    lancelot::xref::XrefType::ConditionalMove => 5,
                }
            }
        }
    }

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyWorkspace {
        fn __str__(&self) -> PyResult<String> {
            PyWorkspace::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!("PyWorkspace(filename: {} loader: {})",
                self.ws.filename.clone(),
                self.ws.loader.get_name(),
            ))
        }
    }


    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PySection {
        fn __str__(&self) -> PyResult<String> {
            PySection::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!("PySection(addr: {:#x} length: {:#x} perms: {:#x} name: {})",
                self.addr,
                self.length,
                self.perms,
                self.name,
            ))
        }
    }

    Ok(())
}


