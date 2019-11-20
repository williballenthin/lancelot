use pyo3::{self, prelude::*, types::PyBytes};
use zydis;

use lancelot::{self, arch::RVA, workspace};

/// if the given expression is an Err, return it as an appropriate type, or
/// ValueError. this is necessary due to the Orphan Rule, due to which we cannot
/// implement From to convert from a Failure::Error to a pyo3::exception.
///
/// the Err type should be failure::Fail.
/// note this returns from the enclosing scope.
macro_rules! pyo3_try {
    ($l:expr) => {
        match $l {
            Err(e) => {
                let name = e.name().unwrap_or("<unknown>").to_string();
                return Err(match e.downcast::<lancelot::workspace::WorkspaceError>() {
                    // we have to use the documentation for the associated routine,
                    // such as `read_u8`, to determine what to inspect here.
                    Ok(lancelot::workspace::WorkspaceError::InvalidAddress) => {
                        pyo3::exceptions::LookupError::py_err("invalid address")
                    }
                    Ok(lancelot::workspace::WorkspaceError::BufferOverrun) => {
                        pyo3::exceptions::LookupError::py_err("buffer overrun")
                    }
                    Ok(lancelot::workspace::WorkspaceError::InvalidInstruction) => {
                        pyo3::exceptions::LookupError::py_err("invalid instruction")
                    }
                    Ok(_) => {
                        // default case: value error
                        pyo3::exceptions::ValueError::py_err(name)
                    }
                    Err(_) => {
                        // default case: value error
                        pyo3::exceptions::ValueError::py_err(name)
                    }
                });
            }
            Ok(v) => v,
        }
    };
}

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
    fn from_bytes(_py: Python, filename: String, buf: &PyBytes) -> PyResult<PyWorkspace> {
        let ws = match workspace::Workspace::from_bytes(&filename, buf.as_bytes()).load() {
            Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to create workspace")),
            Ok(ws) => ws,
        };
        Ok(PyWorkspace { ws })
    }

    #[pyclass]
    pub struct PyWorkspace {
        ws: workspace::Workspace,
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

    m.add("XREF_FALLTHROUGH", 1)?;
    m.add("XREF_CALL", 2)?;
    m.add("XREF_UNCONDITIONAL_JUMP", 3)?;
    m.add("XREF_CONDITIONAL_JUMP", 4)?;
    m.add("XREF_CONDITIONAL_MOVE", 5)?;

    #[pyclass]
    #[derive(Clone)]
    pub struct PyImm {
        #[pyo3(get)]
        pub is_relative: bool,
        #[pyo3(get)]
        pub value: i128, // needs to fit both i64 and u64
    }

    #[pyclass]
    #[derive(Clone)]
    pub struct PyMem {
        #[pyo3(get)]
        pub typ: String, // enum
        #[pyo3(get)]
        pub base: Option<String>, // register, TODO: reuse global constant for this, e.g. `REG_EAX`?
        #[pyo3(get)]
        pub index: Option<String>, // register
        #[pyo3(get)]
        pub segment: Option<String>, // register
        #[pyo3(get)]
        pub scale: u8,
        #[pyo3(get)]
        pub disp: Option<i64>,
    }

    #[pyclass]
    #[derive(Clone)]
    pub struct PyPtr {
        #[pyo3(get)]
        pub offset: u32,
        #[pyo3(get)]
        pub segment: u16,
    }

    #[pyclass]
    #[derive(Clone)]
    pub struct PyOperand {
        #[pyo3(get)]
        pub typ: String,
        #[pyo3(get)]
        pub imm: Option<PyImm>,
        #[pyo3(get)]
        pub mem: Option<PyMem>,
        #[pyo3(get)]
        pub ptr: Option<PyPtr>,
        #[pyo3(get)]
        pub reg: Option<String>,
    }

    #[pyclass]
    #[derive(Clone)]
    pub struct PyInsn {
        #[pyo3(get)]
        pub mnemonic: String,
        #[pyo3(get)]
        pub length: u8,
        #[pyo3(get)]
        pub machine_mode: String,
        #[pyo3(get)]
        pub operands: Vec<PyOperand>,

        raw: zydis::DecodedInstruction,
    }

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
            Ok(self
                .ws
                .module
                .sections
                .iter()
                .map(|section| PySection {
                    addr:   section.addr.into(),
                    length: section.size.into(),
                    perms:  section.perms.bits(),
                    name:   section.name.clone(),
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
            .map(|x| x.into())
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
            .map(|x| x.into())
            .collect())
        }

        /// probe(self, rva, length=1, permissions=PERM_R, /)
        /// --
        ///
        /// Is the given address mapped?
        pub fn probe(&self, rva: i64, length: Option<usize>, perms: Option<u8>) -> PyResult<bool> {
            let length = match length {
                Some(length) => length,
                None => 1,
            };

            let perms = match perms {
                Some(perms) => lancelot::loader::Permissions::from_bits(perms).expect("invalid permissions"),
                None => lancelot::loader::Permissions::R,
            };

            Ok(self.ws.probe(RVA::from(rva), length, perms))
        }

        /// read_bytes(self, rva, length, /)
        /// --
        ///
        /// Read bytes from the given memory address.
        ///
        /// raises:
        ///   - LookupError: if the address is not mapped, or the length
        ///     overruns.
        pub fn read_bytes<'p>(&self, py: Python<'p>, rva: i64, length: usize) -> PyResult<&'p pyo3::types::PyBytes> {
            let buf = pyo3_try!(self.ws.read_bytes(RVA::from(rva), length));
            Ok(pyo3::types::PyBytes::new(py, &buf))
        }

        /// read_u8(self, rva, /)
        /// --
        pub fn read_u8(&self, rva: i64) -> PyResult<u8> {
            Ok(pyo3_try!(self.ws.read_u8(RVA::from(rva))))
        }

        /// read_u16(self, rva, /)
        /// --
        pub fn read_u16(&self, rva: i64) -> PyResult<u16> {
            Ok(pyo3_try!(self.ws.read_u16(RVA::from(rva))))
        }

        /// read_u32(self, rva, /)
        /// --
        pub fn read_u32(&self, rva: i64) -> PyResult<u32> {
            Ok(pyo3_try!(self.ws.read_u32(RVA::from(rva))))
        }

        /// read_u64(self, rva, /)
        /// --
        pub fn read_u64(&self, rva: i64) -> PyResult<u64> {
            Ok(pyo3_try!(self.ws.read_u64(RVA::from(rva))))
        }

        /// read_rva(self, rva, /)
        /// --
        ///
        /// Read the integer relative virtual address at the given address.
        /// The size of the RVA is dependent upon the bitness of the current
        /// workspace.
        pub fn read_rva(&self, rva: i64) -> PyResult<i64> {
            Ok(pyo3_try!(self.ws.read_rva(RVA::from(rva))).into())
        }

        /// read_va(self, rva, /)
        /// --
        ///
        /// Read the integer virtual address at the given address.
        /// The size of the VA is dependent upon the bitness of the current
        /// workspace.
        pub fn read_va(&self, rva: i64) -> PyResult<u64> {
            Ok(pyo3_try!(self.ws.read_va(RVA::from(rva))).into())
        }

        /// read_insn(self, rva, /)
        /// --
        ///
        /// Read an instruction at the given address.
        /// The result is a dictionary that describes the instruction;
        /// its schema is defined by the zydis library.
        ///
        /// raises:
        ///   - LookupError: if the address is not mapped, or the length
        ///     overruns.
        ///   - ValueError: if the instruction cannot be decoded or serialized.
        pub fn read_insn(&self, rva: i64) -> PyResult<PyInsn> {
            match &self.ws.read_insn(RVA::from(rva)) {
                Err(_) => Err(pyo3::exceptions::ValueError::py_err("failed to read insn")),
                Ok(insn) => Ok(insn.into()),
            }
        }

        pub fn get_basic_blocks(&self, rva: i64) -> PyResult<Vec<PyBasicBlock>> {
            Ok(pyo3_try!(self.ws.get_basic_blocks(RVA::from(rva)))
                .iter()
                .map(|bb| bb.into())
                .collect())
        }
    }

    #[pyclass]
    #[derive(Debug, Clone)]
    pub struct PyBasicBlock {
        /// start RVA of the basic block.
        #[pyo3(get)]
        pub addr: i64,

        /// length of the basic block in bytes.
        #[pyo3(get)]
        pub length: u64,

        /// RVAs of start addresses of basic blocks that flow here.
        #[pyo3(get)]
        pub predecessors: Vec<i64>,

        /// RVAs of start addresses of basic blocks that flow from here.
        #[pyo3(get)]
        pub successors: Vec<i64>,

        /// RVAs of instructions found in this basic block.
        #[pyo3(get)]
        pub insns: Vec<i64>,
    }

    impl std::convert::From<&lancelot::BasicBlock> for PyBasicBlock {
        fn from(bb: &lancelot::BasicBlock) -> PyBasicBlock {
            PyBasicBlock {
                addr:         bb.addr.into(),
                length:       bb.length,
                predecessors: bb.predecessors.iter().map(|&p| p.into()).collect(),
                successors:   bb.successors.iter().map(|&p| p.into()).collect(),
                insns:        bb.insns.iter().map(|&p| p.into()).collect(),
            }
        }
    }

    impl std::convert::From<&lancelot::Xref> for PyXref {
        fn from(x: &lancelot::Xref) -> PyXref {
            PyXref {
                src: x.src.into(),
                dst: x.dst.into(),
                typ: match x.typ {
                    lancelot::xref::XrefType::Fallthrough => 1,
                    lancelot::xref::XrefType::Call => 2,
                    lancelot::xref::XrefType::UnconditionalJump => 3,
                    lancelot::xref::XrefType::ConditionalJump => 4,
                    lancelot::xref::XrefType::ConditionalMove => 5,
                },
            }
        }
    }

    impl std::convert::From<&zydis::ffi::DecodedOperand> for PyOperand {
        fn from(operand: &zydis::DecodedOperand) -> PyOperand {
            let mut ret = PyOperand {
                typ: match operand.ty {
                    zydis::enums::OperandType::IMMEDIATE => "imm",
                    zydis::enums::OperandType::MEMORY => "mem",
                    zydis::enums::OperandType::POINTER => "ptr",
                    zydis::enums::OperandType::REGISTER => "reg",
                    zydis::enums::OperandType::UNUSED => "unused",
                }
                .to_string(),
                imm: None,
                mem: None,
                ptr: None,
                reg: None,
            };

            match operand.ty {
                zydis::enums::OperandType::IMMEDIATE => {
                    ret.imm = Some(PyImm {
                        is_relative: operand.imm.is_relative,
                        value:       match operand.imm.is_signed {
                            true => lancelot::util::u64_i64(operand.imm.value) as i128,
                            false => operand.imm.value as i128,
                        },
                    })
                }
                zydis::enums::OperandType::MEMORY => {
                    ret.mem = Some(PyMem {
                        typ:     format!("{:?}", operand.mem.ty).to_lowercase(),
                        base:    match operand.mem.base {
                            zydis::enums::Register::NONE => None,
                            _ => Some(format!("{:?}", operand.mem.base).to_lowercase()),
                        },
                        index:   match operand.mem.index {
                            zydis::enums::Register::NONE => None,
                            _ => Some(format!("{:?}", operand.mem.index).to_lowercase()),
                        },
                        segment: match operand.mem.segment {
                            zydis::enums::Register::NONE => None,
                            _ => Some(format!("{:?}", operand.mem.segment).to_lowercase()),
                        },
                        scale:   operand.mem.scale,
                        disp:    match operand.mem.disp.has_displacement {
                            true => Some(operand.mem.disp.displacement),
                            false => None,
                        },
                    })
                }
                zydis::enums::OperandType::POINTER => {
                    ret.ptr = Some(PyPtr {
                        segment: operand.ptr.segment,
                        offset:  operand.ptr.offset,
                    })
                }
                zydis::enums::OperandType::REGISTER => ret.reg = Some(format!("{:?}", operand.reg).to_lowercase()),
                _ => {}
            }

            ret
        }
    }

    impl std::convert::From<&zydis::ffi::DecodedInstruction> for PyInsn {
        fn from(insn: &zydis::DecodedInstruction) -> PyInsn {
            PyInsn {
                mnemonic:     format!("{:?}", insn.mnemonic).to_lowercase(),
                length:       insn.length,
                machine_mode: format!("{:?}", insn.machine_mode).to_lowercase(),
                operands:     insn
                    .operands
                    .iter()
                    .take(insn.operand_count as usize)
                    .filter(|o| o.visibility == zydis::enums::OperandVisibility::EXPLICIT)
                    .filter(|o| o.ty != zydis::enums::OperandType::UNUSED)
                    .map(|o| o.into())
                    .collect(),
                raw:          insn.clone(),
            }
        }
    }

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyInsn {
        fn __str__(&self) -> PyResult<String> {
            let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();
            let mut buffer = [0u8; 200];
            let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

            match formatter.format_instruction(&self.raw, &mut buffer, None, None) {
                Err(_) => return Err(pyo3::exceptions::ValueError::py_err("failed to render insn")),
                _ => {}
            }

            Ok(format!("{}", buffer))
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!("PyInsn({})", PyInsn::__str__(self)?))
        }
    }

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyWorkspace {
        fn __str__(&self) -> PyResult<String> {
            PyWorkspace::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!(
                "PyWorkspace(filename: {} loader: {})",
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
            Ok(format!(
                "PySection(addr: {:#x} length: {:#x} perms: {:#x} name: {})",
                self.addr, self.length, self.perms, self.name,
            ))
        }
    }

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyXref {
        fn __str__(&self) -> PyResult<String> {
            PyXref::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!(
                "PyXref(src: {:#x} dst: {:#x} type: {})",
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

    #[pyproto]
    impl pyo3::class::basic::PyObjectProtocol for PyBasicBlock {
        fn __str__(&self) -> PyResult<String> {
            PyBasicBlock::__repr__(self)
        }

        fn __repr__(&self) -> PyResult<String> {
            Ok(format!(
                "PyBasicBlock(addr: {:#x} length: {:#x} insns: {})",
                self.addr,
                self.length,
                self.insns.len(),
            ))
        }
    }

    #[pyproto]
    impl pyo3::class::PyMappingProtocol for PyBasicBlock {
        fn __len__(&self) -> PyResult<usize> {
            Ok(self.length as usize)
        }
    }

    Ok(())
}
