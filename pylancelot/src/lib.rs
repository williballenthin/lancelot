#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

use std::ops::Not;

use ::lancelot::{
    analysis::dis::{zydis, Target},
    arch::Arch,
    aspace::AddressSpace,
    loader::{coff::COFFError, pe::PEError},
    module::{ModuleError, Permissions},
    pagemap::PageMapError,
    util::UtilError,
    workspace::{Workspace as lWorkspace, WorkspaceError},
    VA,
};
use anyhow::Error;
use pyo3::{self, prelude::*, types::*, wrap_pyfunction};

/// ValueError -> "you're doing something wrong"
fn to_value_error(e: anyhow::Error) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("{}", e))
}

fn to_py_err(e: Error) -> PyErr {
    #[allow(clippy::single_match)]
    match e.downcast_ref::<WorkspaceError>() {
        Some(WorkspaceError::FormatNotSupported) => return to_value_error(e),
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

/// parse and construct a Workspace instance from the given bytes.
///
/// Args:
///   buf (bytes): the raw bytes of a supported file (e.g., PE or COFF)
///
/// Returns: Workspace
#[pyfunction]
pub fn from_bytes(buf: &PyBytes) -> PyResult<Workspace> {
    use ::lancelot::analysis::dis;

    let config = ::lancelot::workspace::config::empty();

    let ws = ::lancelot::workspace::workspace_from_bytes(config, buf.as_bytes()).map_err(to_py_err)?;
    let dec = dis::get_disassembler(ws.module()).map_err(to_py_err)?;
    Ok(Workspace {
        inner:   ws,
        decoder: dec,
    })
}

/// Control Flow Graph (CFG) is the result of disassembling from a given
/// address. The result is broken up into regions of non-branching instructions
/// ("basic blocks").
#[pyclass]
#[allow(dead_code)]
pub struct CFG {
    /// the address from which this CFG was constructed.
    #[pyo3(get)]
    pub address: u64,

    /// mapping from virtual address to basic block.
    /// type: Dict[int, BasicBlock]
    #[pyo3(get)]
    pub basic_blocks: Py<PyDict>,
}

const TARGET_DIRECT: u8 = 0;
const TARGET_INDIRECT: u8 = 1;

const FLOW_FALLTHROUGH: u8 = 0;
const FLOW_CALL: u8 = 1;
const FLOW_UNCONDITIONAL_JUMP: u8 = 2;
const FLOW_CONDITIONAL_JUMP: u8 = 3;
const FLOW_CONDITIONAL_MOVE: u8 = 4;

fn flow_to_tuple(py: Python, flow: &::lancelot::analysis::cfg::flow::Flow) -> Py<PyTuple> {
    // we use a tuple for performance.
    use ::lancelot::analysis::cfg::flow::Flow;
    let triple: [u64; 3] = match flow {
        Flow::Fallthrough(va) => [*va, TARGET_DIRECT as u64, FLOW_FALLTHROUGH as u64],
        Flow::Call(Target::Direct(va)) => [*va, TARGET_DIRECT as u64, FLOW_CALL as u64],
        Flow::Call(Target::Indirect(va)) => [*va, TARGET_INDIRECT as u64, FLOW_CALL as u64],
        Flow::UnconditionalJump(Target::Direct(va)) => [*va, TARGET_DIRECT as u64, FLOW_UNCONDITIONAL_JUMP as u64],
        Flow::UnconditionalJump(Target::Indirect(va)) => [*va, TARGET_INDIRECT as u64, FLOW_UNCONDITIONAL_JUMP as u64],
        Flow::ConditionalJump(va) => [*va, TARGET_DIRECT as u64, FLOW_CONDITIONAL_JUMP as u64],
    };
    let triple = PyTuple::new(py, triple.iter());
    triple.into()
}

/// A basic block is a region of non-branching instructions (nor target of
/// branches).
#[pyclass]
#[allow(dead_code)]
pub struct BasicBlock {
    /// the starting address of the basic block.
    /// you can use this as an index into the parent `CFG.basic_blocks`.
    #[pyo3(get)]
    pub address: u64,

    /// length in bytes of the basic block.
    #[pyo3(get)]
    pub length: u64,

    /// list of successor Flow instances
    #[pyo3(get)]
    pub successors: Py<PyList>,
}

#[pymethods]
impl BasicBlock {
    fn __int__(&self) -> PyResult<u64> {
        Ok(self.address)
    }
}

/// index into operand tuple
const OPERAND_TYPE: u8 = 0;
const OPERAND_SIZE: u8 = 1;

// type of operand
const OPERAND_TYPE_IMMEDIATE: u8 = 0;
const OPERAND_TYPE_MEMORY: u8 = 1;
const OPERAND_TYPE_POINTER: u8 = 2;
const OPERAND_TYPE_REGISTER: u8 = 3;

/// index into operand tuple when type == immediate
const IMMEDIATE_OPERAND_IS_RELATIVE: u8 = 2;
const IMMEDIATE_OPERAND_VALUE: u8 = 3;

/// index into operand tuple when type == memory
const MEMORY_OPERAND_BASE: u8 = 2;
const MEMORY_OPERAND_INDEX: u8 = 3;
const MEMORY_OPERAND_SEGMENT: u8 = 4;
const MEMORY_OPERAND_SCALE: u8 = 5;
const MEMORY_OPERAND_DISP: u8 = 6;

/// index into operand tuple when type == pointer
const POINTER_OPERAND_SEGEMENT: u8 = 2;
const POINTER_OPERAND_OFFSET: u8 = 3;

/// index into operand tuple when type == reg
const REGISTER_OPERAND_REGISTER: u8 = 2;

fn register_to_py(py: Python, register: zydis::Register) -> PyObject {
    if matches!(register, zydis::Register::NONE) {
        py.None()
    } else {
        format!("{:?}", register).to_lowercase().into_py(py)
    }
}

fn operand_to_tuple(py: Python, operand: &zydis::DecodedOperand) -> Py<PyTuple> {
    let mut ret: Vec<PyObject> = vec![];

    let ty = match operand.ty {
        zydis::enums::OperandType::IMMEDIATE => OPERAND_TYPE_IMMEDIATE,
        zydis::enums::OperandType::MEMORY => OPERAND_TYPE_MEMORY,
        zydis::enums::OperandType::POINTER => OPERAND_TYPE_POINTER,
        zydis::enums::OperandType::REGISTER => OPERAND_TYPE_REGISTER,
        _ => panic!("unexpected operand type"),
    };
    ret.push(ty.into_py(py));

    ret.push(operand.size.into_py(py));

    match operand.ty {
        zydis::enums::OperandType::IMMEDIATE => {
            ret.push(operand.imm.is_relative.into_py(py));
            let value = if operand.imm.is_signed {
                ::lancelot::util::u64_i64(operand.imm.value) as i128
            } else {
                operand.imm.value as i128
            };
            ret.push(value.into_py(py));
        }
        zydis::enums::OperandType::MEMORY => {
            ret.push(register_to_py(py, operand.mem.base));
            ret.push(register_to_py(py, operand.mem.index));
            ret.push(register_to_py(py, operand.mem.segment));
            ret.push(operand.mem.scale.into_py(py));
            if operand.mem.disp.has_displacement {
                ret.push(operand.mem.disp.displacement.into_py(py));
            } else {
                ret.push(py.None());
            }
        }
        zydis::enums::OperandType::POINTER => {
            ret.push(operand.ptr.segment.into_py(py));
            ret.push(operand.ptr.offset.into_py(py));
        }
        zydis::enums::OperandType::REGISTER => {
            ret.push(register_to_py(py, operand.reg));
        }
        _ => {}
    };

    PyTuple::new(py, ret.iter()).into()
}

#[pyclass]
pub struct Instruction {
    /// the starting address of the basic block.
    /// you can use this as an index into the parent `CFG.basic_blocks`.
    #[pyo3(get)]
    address: u64,

    inner: zydis::DecodedInstruction,
}

#[pymethods]
impl Instruction {
    /// the length in bytes of the instruction.
    #[getter]
    pub fn length(&self) -> u8 {
        self.inner.length
    }

    #[getter]
    pub fn mnemonic(&self) -> String {
        format!("{:?}", self.inner.mnemonic).to_lowercase()
    }

    #[getter]
    pub fn operands(&self, py: Python) -> Py<PyTuple> {
        let mut ret: Vec<Py<PyTuple>> = vec![];

        for operand in self.inner.operands.iter() {
            if matches!(operand.ty, zydis::enums::OperandType::UNUSED) {
                continue;
            }
            if matches!(operand.visibility, zydis::enums::OperandVisibility::INVALID) {
                continue;
            }
            if matches!(operand.visibility, zydis::enums::OperandVisibility::HIDDEN) {
                continue;
            }
            ret.push(operand_to_tuple(py, operand));
        }

        PyTuple::new(py, ret.iter()).into()
    }

    fn __str__(&self) -> PyResult<String> {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).expect("formatter");
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);

        formatter
            .format_instruction(&self.inner, &mut buffer, Some(self.address), None)
            .expect("format");
        Ok(format!("{:#x}: {}", self.address, buffer))
    }

    fn __int__(&self) -> PyResult<u64> {
        Ok(self.address)
    }
}

const PERMISSION_READ: u8 = 0b001;
const PERMISSION_WRITE: u8 = 0b010;
const PERMISSION_EXECUTE: u8 = 0b100;

#[pyclass]
pub struct Workspace {
    inner:   Box<dyn lWorkspace>,
    decoder: zydis::Decoder,
}

#[pymethods]
impl Workspace {
    /// fetch the architecture of the PE file as a string.
    /// either "x32" or "x64"
    ///
    /// Returns: str
    #[getter]
    pub fn arch(&self) -> &'static str {
        match self.inner.module().arch {
            Arch::X32 => "x32",
            Arch::X64 => "x64",
        }
    }

    /// fetch the module base address.
    ///
    /// Returns: int
    #[getter]
    pub fn base_address(&self) -> u64 {
        self.inner.module().address_space.base_address
    }

    /// use a collection of heuristics to identify potential function start
    /// addresses. this is done both quickly and on a best-effort basis.
    /// for example, this includes:
    ///   - exported routines
    ///   - targets of `call` instructions
    ///   - function prologue pattern matches
    ///   - targets of pointers to executable sections
    ///   - control flow and safeseh table entries
    ///
    /// the result is a list of virtual addresses where disassembly could start.
    ///
    /// Returns: List[int]
    pub fn get_functions(&self) -> PyResult<Vec<u64>> {
        Ok(self
            .inner
            .analysis()
            .functions
            .iter()
            .filter(|(_, f)| f.flags.contains(::lancelot::workspace::FunctionFlags::THUNK).not())
            .map(|(va, _)| va)
            .cloned()
            .collect())
    }

    pub fn get_thunks(&self) -> PyResult<Vec<u64>> {
        Ok(self
            .inner
            .analysis()
            .functions
            .iter()
            .filter(|(_, f)| f.flags.contains(::lancelot::workspace::FunctionFlags::THUNK))
            .map(|(va, _)| va)
            .cloned()
            .collect())
    }

    /// disassemble from the given virtual address,
    /// collecting ranges of non-branching instructions ("basic blocks").
    /// typically, you'd invoke `Workspace.build_cfg` on the address of a
    /// function start, such as returned by `Workspace.get_functions`.
    ///
    /// does follow jumps, but
    /// does not follow call instructions.
    ///
    /// Args:
    ///   va (int): the address from which to disassemble.
    ///
    /// Returns: CFG
    pub fn build_cfg(&self, py: Python, va: VA) -> PyResult<CFG> {
        use ::lancelot::analysis::cfg;

        let mut insns: cfg::InstructionIndex = Default::default();
        insns.build_index(self.inner.module(), va).map_err(to_py_err)?;
        let cfg = cfg::CFG::from_instructions(self.inner.module(), insns).map_err(to_py_err)?;

        let basic_blocks = PyDict::new(py);
        for (bbva, bb) in cfg.basic_blocks.blocks_by_address.iter() {
            let succs = PyList::empty(py);
            for succ in cfg.flows.flows_by_src[&bb.address_of_last_insn].iter() {
                succs.append(flow_to_tuple(py, succ))?;
            }

            let pybb = BasicBlock {
                address:    bb.address,
                length:     bb.length,
                successors: succs.into(),
            }
            .into_py(py);

            basic_blocks.set_item(bbva, pybb)?;
        }

        Ok(CFG {
            address:      va,
            basic_blocks: basic_blocks.into(),
        })
    }

    /// read a sequence of bytes at the given virtual address.
    ///
    /// Args:
    ///   va (int): the virtual address at which to read data.
    ///   length (int): the number of bytes to read.
    ///
    /// Raises:
    ///   ValueError - if the address is invalid.
    ///
    /// Returns: bytes
    pub fn read_bytes(&self, py: Python, va: VA, length: usize) -> PyResult<Py<PyBytes>> {
        self.inner
            .module()
            .address_space
            .read_bytes(va, length)
            .map(|buf| PyBytes::new(py, &buf).into())
            .map_err(to_py_err)
    }

    /// disassemble an instruction at the given virtual address.
    ///
    /// Args:
    ///   va (int): the virtual address at which to disassemble.
    ///
    /// Raises:
    ///   ValueError - if the address or instruction is invalid.
    ///
    /// Returns: Instruction
    pub fn read_insn(&self, va: VA) -> PyResult<Instruction> {
        let mut insn_buf = [0u8; 16];
        self.inner
            .module()
            .address_space
            .read_into(va, &mut insn_buf)
            .map_err(to_py_err)?;

        if let Ok(Some(insn)) = self.decoder.decode(&insn_buf) {
            Ok(Instruction {
                address: va,
                inner:   insn,
            })
        } else {
            Err(pyo3::exceptions::PyValueError::new_err("invalid instruction"))
        }
    }

    /// read a pointer at the given virtual address.
    ///
    /// Args:
    ///   va (int): the virtual address at which to read the pointer.
    ///
    /// Raises:
    ///   ValueError - if the address is invalid.
    ///
    /// Returns: int
    pub fn read_pointer(&self, va: VA) -> PyResult<u64> {
        self.inner.module().read_va_at_va(va).map_err(to_py_err)
    }

    pub fn probe(&self, va: i128) -> u8 {
        // probe should be pretty relaxed about what it accepts
        // so that it is easy to use.
        // therefore, do extra validation here.
        if va < 0 {
            return 0x0;
        }
        if va > u64::MAX as i128 {
            return 0x0;
        }
        let va = va as u64;

        match self
            .inner
            .module()
            .sections
            .iter()
            .find(|section| section.virtual_range.contains(&va))
        {
            None => 0x0,
            Some(sec) => {
                let mut ret = 0;
                if sec.permissions.intersects(Permissions::R) {
                    ret |= PERMISSION_READ;
                }

                if sec.permissions.intersects(Permissions::W) {
                    ret |= PERMISSION_WRITE;
                }

                if sec.permissions.intersects(Permissions::X) {
                    ret |= PERMISSION_EXECUTE;
                }
                ret
            }
        }
    }
}

#[pymodule]
fn lancelot(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(from_bytes, m)?)?;
    m.add_class::<Workspace>()?;

    // indices into a flow tuple
    m.add("FLOW_VA", 0)?;
    m.add("FLOW_TARGET", 1)?;
    m.add("FLOW_TYPE", 2)?;

    // flow types
    // we use int constants for performance
    m.add("TARGET_DIRECT", TARGET_DIRECT)?;
    m.add("TARGET_INDIRECT", TARGET_INDIRECT)?;

    // flow types
    // we use int constants for performance
    m.add("FLOW_TYPE_FALLTHROUGH", FLOW_FALLTHROUGH)?;
    m.add("FLOW_TYPE_CALL", FLOW_CALL)?;
    m.add("FLOW_TYPE_UNCONDITIONAL_JUMP", FLOW_UNCONDITIONAL_JUMP)?;
    m.add("FLOW_TYPE_CONDITIONAL_JUMP", FLOW_CONDITIONAL_JUMP)?;
    m.add("FLOW_TYPE_CONDITIONAL_MOVE", FLOW_CONDITIONAL_MOVE)?;

    // indices into an operand tuple
    m.add("OPERAND_TYPE", OPERAND_TYPE)?;
    m.add("OPERAND_SIZE", OPERAND_SIZE)?;
    m.add("IMMEDIATE_OPERAND_IS_RELATIVE", IMMEDIATE_OPERAND_IS_RELATIVE)?;
    m.add("IMMEDIATE_OPERAND_VALUE", IMMEDIATE_OPERAND_VALUE)?;
    m.add("MEMORY_OPERAND_BASE", MEMORY_OPERAND_BASE)?;
    m.add("MEMORY_OPERAND_INDEX", MEMORY_OPERAND_INDEX)?;
    m.add("MEMORY_OPERAND_SEGMENT", MEMORY_OPERAND_SEGMENT)?;
    m.add("MEMORY_OPERAND_SCALE", MEMORY_OPERAND_SCALE)?;
    m.add("MEMORY_OPERAND_DISP", MEMORY_OPERAND_DISP)?;
    m.add("POINTER_OPERAND_SEGEMENT", POINTER_OPERAND_SEGEMENT)?;
    m.add("POINTER_OPERAND_OFFSET", POINTER_OPERAND_OFFSET)?;
    m.add("REGISTER_OPERAND_REGISTER", REGISTER_OPERAND_REGISTER)?;

    // operand types
    // we use int constants for performance
    m.add("OPERAND_TYPE_IMMEDIATE", OPERAND_TYPE_IMMEDIATE)?;
    m.add("OPERAND_TYPE_MEMORY", OPERAND_TYPE_MEMORY)?;
    m.add("OPERAND_TYPE_POINTER", OPERAND_TYPE_POINTER)?;
    m.add("OPERAND_TYPE_REGISTER", OPERAND_TYPE_REGISTER)?;

    // memory permissions
    m.add("PERMISSION_READ", PERMISSION_READ)?;
    m.add("PERMISSION_WRITE", PERMISSION_WRITE)?;
    m.add("PERMISSION_EXECUTE", PERMISSION_EXECUTE)?;

    Ok(())
}
