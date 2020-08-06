use anyhow::Error;
use lancelot::{
    loader::pe::{PEError, PE as lPE},
    module::ModuleError,
    pagemap::PageMapError,
    util::UtilError,
    VA,
};
use pyo3::{self, prelude::*, types::*, wrap_pyfunction};

/// ValueError -> "you're doing something wrong"
fn to_value_error(e: anyhow::Error) -> PyErr {
    pyo3::exceptions::ValueError::py_err(format!("{}", e))
}

fn to_py_err(e: Error) -> PyErr {
    match e.downcast_ref::<PEError>() {
        Some(PEError::FormatNotSupported(_)) => return to_value_error(e),
        Some(PEError::MalformedPEFile(_)) => return to_value_error(e),
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

/// parse and construct a PE instance from the given bytes.
///
/// Args:
///   buf (bytes): the raw bytes of a PE file.
///
/// Returns: PE
#[pyfunction]
pub fn from_bytes(buf: &PyBytes) -> PyResult<PE> {
    Ok(PE {
        inner: lPE::from_bytes(buf.as_bytes()).map_err(to_py_err)?,
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

const FLOW_FALLTHROUGH: u64 = 0;
const FLOW_CALL: u64 = 1;
const FLOW_UNCONDITIONAL_JUMP: u64 = 2;
const FLOW_CONDITIONAL_JUMP: u64 = 3;
const FLOW_CONDITIONAL_MOVE: u64 = 4;

fn flow_to_tuple(py: Python, flow: &lancelot::analysis::cfg::Flow) -> PyResult<Py<PyTuple>> {
    // we use a tuple for performance.
    use lancelot::analysis::cfg::Flow;
    let pair: [u64; 2] = match flow {
        Flow::Fallthrough(va) => [*va, FLOW_FALLTHROUGH],
        Flow::Call(va) => [*va, FLOW_CALL],
        Flow::UnconditionalJump(va) => [*va, FLOW_UNCONDITIONAL_JUMP],
        Flow::ConditionalJump(va) => [*va, FLOW_CONDITIONAL_JUMP],
        Flow::ConditionalMove(va) => [*va, FLOW_CONDITIONAL_MOVE],
    };
    let pair = PyTuple::new(py, pair.iter());
    Ok(pair.into())
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

    /// list of tuples (virtual address, flow type) of basic blocks that flow to
    /// this basic block. the virtual address can be used as an index into
    /// the parent `CFG.basic_blocks`. the flow type is one of the
    /// `FLOW_TYPE_*` constants, such as `FLOW_TYPE_CALL`.
    /// use the `FLOW_(VA|TYPE)` constants to index into this tuple
    /// type: List[Tuple[int, int]]
    #[pyo3(get)]
    pub predecessors: Py<PyList>,

    /// list of tuples (virtual address, flow type) of basic blocks that flow
    /// from this basic block. type: List[Tuple[int, int]]
    #[pyo3(get)]
    pub successors: Py<PyList>,
}

impl BasicBlock {
    fn from_basic_block(py: Python, bb: &lancelot::analysis::cfg::BasicBlock) -> PyResult<BasicBlock> {
        let predecessors = PyList::empty(py);
        let successors = PyList::empty(py);

        for pred in bb.predecessors.iter() {
            let pair = flow_to_tuple(py, pred)?;
            predecessors.append(pair)?;
        }

        for succ in bb.successors.iter() {
            let pair = flow_to_tuple(py, succ)?;
            successors.append(pair)?;
        }

        Ok(BasicBlock {
            address:      bb.addr,
            length:       bb.length,
            predecessors: predecessors.into(),
            successors:   successors.into(),
        })
    }
}

#[pyclass]
pub struct PE {
    inner: lPE,
}

#[pymethods]
impl PE {
    /// fetch the architecture of the PE file as a string.
    /// either "x32" or "x64"
    ///
    /// Returns: str
    #[getter]
    pub fn arch(&self) -> PyResult<&'static str> {
        Ok(match self.inner.module.arch {
            lancelot::module::Arch::X32 => "x32",
            lancelot::module::Arch::X64 => "x64",
        })
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
        lancelot::analysis::pe::find_function_starts(&self.inner).map_err(to_py_err)
    }

    /// disassemble from the given virtual address,
    /// collecting ranges of non-branching instructions ("basic blocks").
    /// typically, you'd invoke `PE.build_cfg` on the address of a function
    /// start, such as returned by `PE.get_functions`.
    ///
    /// does follow jumps, but
    /// does not follow call instructions.
    ///
    /// Args:
    ///   va (int): the address from which to disassemble.
    ///
    /// Returns: CFG
    pub fn build_cfg(&self, py: Python, va: VA) -> PyResult<CFG> {
        let basic_blocks = PyDict::new(py);
        let cfg = lancelot::analysis::cfg::build_cfg(&self.inner.module, va).map_err(to_py_err)?;

        for (bbva, bb) in cfg.basic_blocks.iter() {
            let bb: PyObject = BasicBlock::from_basic_block(py, bb)?.into_py(py);
            basic_blocks.set_item(bbva, bb)?;
        }

        Ok(CFG {
            address:      va,
            basic_blocks: basic_blocks.into(),
        })
    }
}

#[pymodule]
fn lancelot(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(from_bytes))?;
    m.add_class::<PE>()?;

    // indices into a flow tuple
    m.add("FLOW_VA", 0)?;
    m.add("FLOW_TYPE", 1)?;

    // we use int constants for performance
    m.add("FLOW_TYPE_FALLTHROUGH", FLOW_FALLTHROUGH)?;
    m.add("FLOW_TYPE_CALL", FLOW_CALL)?;
    m.add("FLOW_TYPE_UNCONDITIONAL_JUMP", FLOW_UNCONDITIONAL_JUMP)?;
    m.add("FLOW_TYPE_CONDITIONAL_JUMP", FLOW_CONDITIONAL_JUMP)?;
    m.add("FLOW_TYPE_CONDITIONAL_MOVE", FLOW_CONDITIONAL_MOVE)?;

    Ok(())
}
