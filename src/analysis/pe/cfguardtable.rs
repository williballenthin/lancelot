/// this analyzer parses the Control Flow Guard function table.
/// it populates functions in the workspace.
/// the purpose of the table is to enumerate the functions that may be called indirectly.
///
/// references:
///   - https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory
///   - https://lucasg.github.io/2017/02/05/Control-Flow-Guard/

use num::{FromPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::{Arch, rva_add_usize};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct CFGuardTableAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> CFGuardTableAnalyzer<A> {
    pub fn new() -> CFGuardTableAnalyzer<A> {
        CFGuardTableAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF0000000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;

impl<A: Arch + 'static> Analyzer<A> for CFGuardTableAnalyzer<A> {
    fn get_name(&self) -> String {
        "CF Guard Table analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::CFGuardTableAnalyzer;
    ///
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// CFGuardTableAnalyzer::<Arch64>::new().analyze(&mut ws);
    ///
    /// // export: RtlVirtualUnwind
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x1010).is_some());
    ///
    /// // __guard_check_icall
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x21960).is_some());
    ///
    /// // __guard_dispatch_icall
    /// assert!(ws.get_functions().find(|&&rva| rva == 0x21B40).is_some());
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
        let (load_config_directory, is_64) = {
            let pe = match Object::parse(&ws.buf) {
                Ok(Object::PE(pe)) => pe,
                _ => panic!("can't analyze unexpected format"),
            };

            let opt_header = match pe.header.optional_header {
                Some(opt_header) => opt_header,
                _ => return Ok(()),
            };

            let load_config_directory = match opt_header.data_directories.get_load_config_table() {
                Some(load_config_directory) => load_config_directory,
                _ => return Ok(()),
            };

            (A::RVA::from_u32(load_config_directory.virtual_address).unwrap(), pe.is_64)
        };

        debug!("load config directory: {:#x}", load_config_directory);

        // offsets defined here:
        // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory

        let cfg_flags = match is_64 {
            true => ws.read_u32(rva_add_usize::<A>(load_config_directory, 144).unwrap())?,
            false => ws.read_u32(rva_add_usize::<A>(load_config_directory, 88).unwrap())?,
        };

        let stride = (cfg_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;

        let cfg_table_va = match is_64 {
            true => ws.read_va(rva_add_usize::<A>(load_config_directory, 128).unwrap())?,
            false => ws.read_va(rva_add_usize::<A>(load_config_directory, 80).unwrap())?,
        };

        let cfg_table_count = match is_64 {
            true => ws.read_u32(rva_add_usize::<A>(load_config_directory, 136).unwrap())?,
            false => ws.read_u32(rva_add_usize::<A>(load_config_directory, 84).unwrap())?,
        };

        let cfg_table_rva = ws.rva(cfg_table_va).unwrap();
        let mut offset = cfg_table_rva;

        for _ in 0..cfg_table_count {
            let function = A::RVA::from_u32(ws.read_u32(offset)?).unwrap();

            debug!("CF guard function: {:#x}", function);
            ws.make_function(function)?;
            ws.analyze()?;

            // 4 == sizeof(32-bit RVA)
            offset = rva_add_usize::<A>(offset, 4 + stride as usize).unwrap();
        }

        // add function pointed to by GuardCFCheckFunctionPointer
        let guard_check_icall_fptr = match is_64 {
            true => ws.rva(ws.read_va(rva_add_usize::<A>(load_config_directory, 112).unwrap())?).unwrap(),
            false => ws.rva(ws.read_va(rva_add_usize::<A>(load_config_directory, 72).unwrap())?).unwrap(),
        };
        if ws.probe(guard_check_icall_fptr, 8) {
            let guard_check_icall = ws.rva(ws.read_va(guard_check_icall_fptr)?).unwrap();
            if ws.probe(guard_check_icall, 1) {
                debug!("CF guard check function: {:#x}", guard_check_icall);
                ws.make_function(guard_check_icall)?;
                ws.analyze()?;
            }
        };

        // add function pointed to by GuardCFDispatchFunctionPointer
        let guard_dispatch_icall_fptr = match is_64 {
            true => ws.rva(ws.read_va(rva_add_usize::<A>(load_config_directory, 120).unwrap())?).unwrap(),
            false => ws.rva(ws.read_va(rva_add_usize::<A>(load_config_directory, 76).unwrap())?).unwrap(),
        };
        if ws.probe(guard_dispatch_icall_fptr, 8) {
            let guard_dispatch_icall = ws.rva(ws.read_va(guard_dispatch_icall_fptr)?).unwrap();
            if ws.probe(guard_dispatch_icall, 1) {
                debug!("CF guard dispatch function: {:#x}", guard_dispatch_icall);
                ws.make_function(guard_dispatch_icall)?;
                ws.analyze()?;
            }
        };

        Ok(())
    }
}
