pub mod entrypoint;
pub use entrypoint::EntryPointAnalyzer;

pub mod exports;
pub use exports::ExportsAnalyzer;

pub mod imports;
pub use imports::ImportsAnalyzer;

pub mod relocs;
pub use relocs::RelocAnalyzer;

pub mod runtimefunctions;
pub use runtimefunctions::RuntimeFunctionAnalyzer;

pub mod cfguardtable;
pub use cfguardtable::CFGuardTableAnalyzer;


// TODO: analyzer for global ctors, initializers (__initterm_e, __initterm)
// TODO: analyzer for import thunks
// TODO: analyzer for TLS callbacks
// TODO: analyzer for switch tables (e.g. 748aa5fcfa2af451c76039faf6a8684d:10001AD8)
// TODO: analyzer for non-returning functions
// TODO: analyzer for code referenced from LoadConfig:
//   - ULONGLONG  SEHandlerTable;                 // VA
//   - ULONGLONG  SEHandlerCount;

// heuristic:
// TODO: analyzer to inspect operands for pointers into the text section, e.g. argument to CreateThread
// TODO: analyzer for jump-tables, ptr tables, see vivisect/pointertables.py
// TODO: analyzer to scan for prologues
// TODO: analyzer for RTTI
// TODO: analyzer for VEH
// TODO: analyzer for SEH
// TODO: analyzer for FLIRT-like signatures to set function names

// TODO: anomaly analyzer for non-contiguous functions
//   e.g. __security_init_cookie in 07FB252D2E853A9B1B32F30EDE411F2EFBB9F01E4A7782DB5EACF3F55CF34902
