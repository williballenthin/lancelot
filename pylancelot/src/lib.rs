use serde_json;

use pyo3;
use pyo3::types::{PyBytes};
use pyo3::types::IntoPyDict;
use pyo3::prelude::*;
use failure::{Error};
use zydis;

use lancelot::workspace;
use lancelot::arch::{RVA};
use lancelot::xref::{XrefType};


/// if the given expression is an Err, return it as a ValueError.
///
/// the Err type should be failure::Fail.
/// note this returns from the enclosing scope.
macro_rules! try_or_value_error {
    ($l:expr) => {match $l {
      Err(e) => return Err(pyo3::exceptions::ValueError::py_err(e.name().unwrap_or("<unknown>").to_string())),
      Ok(v) => v,
    }}
}

const EMPTY_OPERAND: zydis::DecodedOperand = zydis::DecodedOperand {
    id: 255,
    ty: zydis::enums::OperandType::UNUSED,
    visibility: zydis::enums::OperandVisibility::HIDDEN,
    action: zydis::enums::OperandAction::READWRITE,
    encoding: zydis::enums::OperandEncoding::NONE,
    size: 0,
    element_type: zydis::enums::ElementType::INVALID,
    element_size: 0,
    element_count: 0,
    reg: zydis::enums::Register::NONE,
    mem: zydis::ffi::MemoryInfo {
        ty: zydis::enums::OperandType::UNUSED,
        segment: zydis::enums::Register::NONE,
        base: zydis::enums::Register::NONE,
        index: zydis::enums::Register::NONE,
        scale: 0,
        disp: zydis::ffi::DisplacementInfo {
            has_displacement: false,
            displacement: 0
        }
    },
    ptr: zydis::ffi::PointerInfo {
        segment: 0,
        offset: 0
    },
    imm: zydis::ffi::ImmediateInfo {
        is_signed: false,
        is_relative: false,
        value: 0
    }
};


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
        #[pyo3(get)]
        pub src: i64,
        #[pyo3(get)]
        pub dst: i64,
        /// one of XREF_* constants
        #[pyo3(get)]
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
        /// sections(self, /)
        /// --
        ///
        /// Fetch the sections loaded from the module.
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
        /// functions(self, /)
        /// --
        ///
        /// Fetch the addresses of functions discovered during analysis.
        pub fn functions(&self) -> PyResult<Vec<i64>> {
            Ok(self.ws.get_functions().map(|&rva| rva.into()).collect())
        }

        /// get_xrefs_from(self, rva, /)
        /// --
        ///
        /// Fetch the xrefs flowing from the given address.
        pub fn get_xrefs_from(&self, rva: i64) -> PyResult<Vec<PyXref>> {
            Ok(match self.ws.get_xrefs_from(RVA::from(rva)) {
                   Ok(xrefs) => xrefs,
                   Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to fetch xrefs")),
               }
               .iter()
               .map(|x| PyWorkspace::translate_xref(x))
               .collect())
        }

        /// get_xrefs_to(self, rva, /)
        /// --
        ///
        /// Fetch the xrefs flowing to the given address.
        pub fn get_xrefs_to(&self, rva: i64) -> PyResult<Vec<PyXref>> {
            Ok(match self.ws.get_xrefs_to(RVA::from(rva)) {
                   Ok(xrefs) => xrefs,
                   Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to fetch xrefs")),
               }
               .iter()
               .map(|x| PyWorkspace::translate_xref(x))
               .collect())
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

        /// read_insn(self, rva, /)
        /// --
        ///
        /// Read an instruction at the given address.
        /// The result is a dictionary that describes the instruction;
        /// its schema is defined by the zydis library.
        ///
        /// raises:
        ///   - LookupError: if the address is not mapped, or the length overruns.
        ///   - ValueError: if the instruction cannot be decoded or serialized.
        pub fn read_insn<'p>(&self, py: Python<'p>, rva: i64) -> PyResult<&'p pyo3::types::PyAny> {
            let mut insn = match self.ws.read_insn(RVA::from(rva)) {
                Ok(insn) => insn,
                Err(e) => return Err(PyWorkspace::translate_buffer_error(e)),
            };

            // seems some of the operands are not initialized,
            // which causes serialization to crash (maybe due to unexpected enum values?).
            //
            // quickfix: overwrite the unused operands with empty values.
            //
            // ref: https://github.com/zyantific/zydis-rs/issues/21
            for i in insn.operand_count..10 {
                insn.operands[i as usize] = EMPTY_OPERAND;
            }

            // rather than manually construct a PyDict that contains the instruction representation
            // (which would be tedious to do)
            // we serialize the instruction to json in rust-land,
            // use json.loads in python land,
            // and pass the resulting PyAny back into the interpreter.
            //
            // the performance here is suspect; however, the developer experience is much better.
            //
            // TODO: signed values, such as operand.imm.value, should be correctly provided.
            // as is, there's a flag that indicates that the unsigned value must be re-interpreted.
            // TODO: might want to add helpers on the insn class, such as to render it.

            let json = match serde_json::to_string(&insn) {
                Ok(s) => s,
                Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to serialize instruction")),
            };

            // this is the serialized EMPTY_OPERAND,
            // which is found in the operand list.
            // so we cut it out of the json document because:
            //   1. these operands won't ever be used, and
            //   2. they have to be parsed and allocated, which is bad for performance.
            let json = json.replace("{\"id\":255,\"ty\":\"UNUSED\",\"visibility\":\"HIDDEN\",\"action\":\"READWRITE\",\"encoding\":\"NONE\",\"size\":0,\"element_type\":\"INVALID\",\"element_size\":0,\"element_count\":0,\"reg\":\"NONE\",\"mem\":{\"ty\":\"UNUSED\",\"segment\":\"NONE\",\"base\":\"NONE\",\"index\":\"NONE\",\"scale\":0,\"disp\":{\"has_displacement\":false,\"displacement\":0}},\"ptr\":{\"segment\":0,\"offset\":0},\"imm\":{\"is_signed\":false,\"is_relative\":false,\"value\":0}},", "");

            // similar chop for empty elements in the .raw.prefixes array.
            let json = json.replace("{\"ty\":\"IGNORED\",\"value\":0},", "");

            // would be nice not to re-import this with each call;
            // however, I'm not sure if its feasible to keep this reference around.
            // also, import should be optimized for when the module is already loaded.
            let globals = [
                ("json", py.import("json")?),
            ].into_py_dict(py);

            let locals = [
                ("doc", json)
            ].into_py_dict(py);

            py.eval("json.loads(doc)", Some(&globals), Some(&locals))
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
                Ok(lancelot::workspace::WorkspaceError::InvalidInstruction) => {
                    pyo3::exceptions::LookupError::py_err("invalid instruction")
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

        fn translate_xref(x: &lancelot::Xref) -> PyXref {
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

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyXref {
        fn __str__(&self) -> PyResult<String> {
            PyXref::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!("PyXref(src: {:#x} dst: {:#x} type: {})",
                self.src,
                self.dst,
                match self.typ {
                    1 => "XREF_FALLTHROUGH",
                    2 => "XREF_CALL",
                    3 => "XREF_UNCONDITIONAL_JUMP",
                    4 => "XREF_CONDITIONAL_JUMP",
                    5 => "XREF_CONDITIONAL_MOVE",
                    _ => unreachable!(),
                },
            ))
        }
    }

    Ok(())
}
