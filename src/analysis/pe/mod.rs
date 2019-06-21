pub mod entrypoint;
pub use entrypoint::EntryPointAnalyzer;

pub mod exports;
pub use exports::ExportsAnalyzer;

pub mod imports;
pub use imports::ImportsAnalyzer;

pub mod ptrs;
pub use ptrs::PtrAnalyzer;

pub mod runtimefunctions;
pub use runtimefunctions::RuntimeFunctionAnalyzer;


// TODO: analyzer for orphan instructions (no predecessors) to functions
// TODO: analyzer for jump-tables, ptr tables, see vivisect/pointertables.py
// TODO: analyzer for __guard_fids_table
// TODO: analyzer for global ctors, initializers (__initterm_e, __initterm)
// TODO: analyzer for import thunks
// TODO: analyzer for TLS callbacks
// TODO: analyzer to inspect operands for pointers into the text section, e.g. argument to CreateThread
// TODO: analyzer to scan for prologues
// TODO: analyzer for RTTI
// TODO: analyzer for non-returning functions
// TODO: analyzer for VEH
// TODO: analyzer for SEH
// TODO: analyzer for FLIRT-like signatures to set function names

// TODO: analyzer for non-contiguous functions
//   e.g. __security_init_cookie in 07FB252D2E853A9B1B32F30EDE411F2EFBB9F01E4A7782DB5EACF3F55CF34902

// for k32.dll, the entrypoint + exports does not catch 0x1800012d4
// this is because its called by sub_180001630
// this has no CALL xref-to.
// it does have:
//   - RUNTIME_FUNCTION at 1800AB06C
//   - __guard_fids_table entry at 18007ABAC (TODO: analysis pass: guard fids table)
//   - function pointer at 1800779E0 (TODO: analysis pass: ptr from data->text)
