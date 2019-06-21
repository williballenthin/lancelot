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


// TODO: analyzer for __guard_fids_table
//  ref: https://lucasg.github.io/2017/02/05/Control-Flow-Guard/
//  ref: https://lifeinhex.com/control-flow-guard-in-windows-8-1-and-vs2015/
//  ref: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory
// TODO: analyzer for global ctors, initializers (__initterm_e, __initterm)
// TODO: analyzer for import thunks
// TODO: analyzer for TLS callbacks
// TODO: analyzer for switch tables (e.g. 748aa5fcfa2af451c76039faf6a8684d:10001AD8)
// TODO: analyzer for non-returning functions
// TODO: analyzer for code referenced from LoadConfig:
//   - ULONGLONG  SEHandlerTable;                 // VA
//   - ULONGLONG  SEHandlerCount;
//   - ULONGLONG  GuardCFCheckFunctionPointer;    // VA
//   - ULONGLONG  GuardCFDispatchFunctionPointer; // VA
//   - ULONGLONG  GuardCFFunctionTable;           // VA
//   - ULONGLONG  GuardCFFunctionCount;
//   - ULONGLONG  GuardAddressTakenIatEntryTable; // VA
//   - ULONGLONG  GuardAddressTakenIatEntryCount;
//   - ULONGLONG  GuardLongJumpTargetTable;       // VA
//   - ULONGLONG  GuardLongJumpTargetCount;
//   - ULONGLONG  DynamicValueRelocTable;         // VA
//   - ULONGLONG  HybridMetadataPointer;          // VA
// ref: https://lucasg.github.io/2017/02/05/Control-Flow-Guard/

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
