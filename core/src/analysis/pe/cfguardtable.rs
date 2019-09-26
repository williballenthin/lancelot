/// this analyzer parses the Control Flow Guard function table.
/// it populates functions in the workspace.
/// the purpose of the table is to enumerate the functions that may be called indirectly.
///
/// references:
///   - https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory
///   - https://lucasg.github.io/2017/02/05/Control-Flow-Guard/
use log::{debug};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::{RVA, VA};
use super::super::super::loader::{Permissions};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct CFGuardTableAnalyzer {}

impl CFGuardTableAnalyzer {
    pub fn new() -> CFGuardTableAnalyzer {
        CFGuardTableAnalyzer {}
    }
}

const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF0000000;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;

impl Analyzer for CFGuardTableAnalyzer {
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
    /// let mut ws = Workspace::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// CFGuardTableAnalyzer::new().analyze(&mut ws);
    ///
    /// // export: RtlVirtualUnwind
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x1010)).is_some());
    ///
    /// // __guard_check_icall
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x21960)).is_some());
    ///
    /// // __guard_dispatch_icall
    /// assert!(ws.get_functions().find(|&&rva| rva == RVA(0x21B40)).is_some());
    /// ```
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
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

            (RVA::from(load_config_directory.virtual_address as i64), pe.is_64)
        };

        debug!("load config directory: {}", load_config_directory);

        // offsets defined here:
        // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#load-configuration-directory

        let cfg_flags = match is_64 {
            true => ws.read_u32(load_config_directory + 0x90)?,
            false => ws.read_u32(load_config_directory + 0x58)?,
        };

        let stride = (cfg_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;

        let cfg_table_va = match is_64 {
            true => ws.read_va(load_config_directory + 0x80)?,
            false => ws.read_va(load_config_directory + 0x50)?,
        };
        debug!("CF Guard table: {}", cfg_table_va);

        let cfg_table_count = match is_64 {
            true => ws.read_u32(load_config_directory + 0x88)?,
            false => ws.read_u32(load_config_directory + 0x54)?,
        };
        debug!("CF Guard table count: {}", cfg_table_count);

        if cfg_table_va == VA(0x0) {
            debug!("CF guard table empty");
            return Ok(())
        };

        let cfg_table_rva = ws.rva(cfg_table_va).unwrap();
        debug!("CF guard table: {}", cfg_table_rva);

        let mut offset = cfg_table_rva;
        for _ in 0..cfg_table_count {
            let function = RVA::from(ws.read_i32(offset)?);

            debug!("CF guard function: {}", function);
            ws.make_function(function)?;
            ws.analyze()?;

            // 4 == sizeof(32-bit RVA)
            offset = offset + (4 + stride as usize);
        }

        // add function pointed to by GuardCFCheckFunctionPointer
        let guard_check_icall_fptr = match is_64 {
            true => ws.rva(ws.read_va(load_config_directory + 112)?).unwrap(),
            false => ws.rva(ws.read_va(load_config_directory + 72)?).unwrap(),
        };
        if ws.probe(guard_check_icall_fptr, 8, Permissions::R) {
            let guard_check_icall = ws.rva(ws.read_va(guard_check_icall_fptr)?).unwrap();
            if ws.probe(guard_check_icall, 1, Permissions::X) {
                debug!("CF guard check function: {:#x}", guard_check_icall);
                ws.make_function(guard_check_icall)?;
                ws.analyze()?;
            }
        };

        // add function pointed to by GuardCFDispatchFunctionPointer
        let guard_dispatch_icall_fptr = match is_64 {
            true => ws.rva(ws.read_va(load_config_directory + 120)?).unwrap(),
            false => ws.rva(ws.read_va(load_config_directory + 76)?).unwrap(),
        };
        if ws.probe(guard_dispatch_icall_fptr, 8, Permissions::R) {
            let guard_dispatch_icall = ws.rva(ws.read_va(guard_dispatch_icall_fptr)?).unwrap();
            if ws.probe(guard_dispatch_icall, 1, Permissions::X) {
                debug!("CF guard dispatch function: {:#x}", guard_dispatch_icall);
                ws.make_function(guard_dispatch_icall)?;
                ws.analyze()?;
            }
        };

        Ok(())
    }
}
