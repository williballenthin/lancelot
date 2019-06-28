use log::{debug};
use goblin::{Object};
use failure::{Error};
use byteorder::{ByteOrder, LittleEndian};

use super::super::super::arch::{RVA};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct RuntimeFunctionAnalyzer {}

impl RuntimeFunctionAnalyzer {
    pub fn new() -> RuntimeFunctionAnalyzer {
        RuntimeFunctionAnalyzer {}
    }
}


struct RuntimeFunction {
    begin_address: RVA,
    end_address: RVA,
    unwind_data: RVA,
}


impl std::fmt::Debug for RuntimeFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RUNTIME_FUNCTION(begin: {:#x} end: {:#x} data: {:#x})",
               self.begin_address,
               self.end_address,
               self.unwind_data
        )
    }
}


impl Analyzer for RuntimeFunctionAnalyzer {
    fn get_name(&self) -> String {
        "RUNTIME_FUNCTION analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::RuntimeFunctionAnalyzer;
    ///
    /// let mut ws = Workspace::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = RuntimeFunctionAnalyzer::new();
    /// anal.analyze(&mut ws).unwrap();
    ///
    /// assert!(ws.get_meta(0x72A70).unwrap().is_insn());
    ///
    /// // this function is referenced in RUNTIME_FUNCTIONs,
    /// // and in code, tail jump at 0x1800112C2
    /// //
    /// //     .text:00000001800112C2     jmp     sub_1800019C8
    /// //
    /// assert!(ws.get_meta(0x19C8).unwrap().is_insn());
    /// ```
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let (exception_directory, directory_size) = {
            let pe = match Object::parse(&ws.buf) {
                Ok(Object::PE(pe)) => pe,
                _ => panic!("can't analyze unexpected format"),
            };

            let opt_header = match pe.header.optional_header {
                Some(opt_header) => opt_header,
                _ => return Ok(()),
            };

            let exception_directory = match opt_header.data_directories.get_exception_table() {
                Some(exception_directory) => exception_directory,
                _ => return Ok(()),
            };

            (RVA::from(exception_directory.virtual_address as i64), exception_directory.size)
        };

        debug!("exception directory: {:#x}", exception_directory);

        let buf = ws.read_bytes(exception_directory, directory_size as usize)?;
        let functions: Vec<RVA> = buf
            .chunks_exact(3 * 4)
            .map(|b| RuntimeFunction{
                begin_address: RVA::from(LittleEndian::read_i32(b)),
                end_address: RVA::from(LittleEndian::read_i32(&b[4..])),
                unwind_data: RVA::from(LittleEndian::read_i32(&b[8..])),
            })
            .filter(|rt| {
                if ! ws.probe(rt.begin_address, 1) {
                    return false;
                }
                if ! ws.probe(rt.end_address, 1) {
                    return false;
                }
                if ! ws.probe(rt.unwind_data, 1) {
                    return false;
                }
                return true;
            })
            .map(|rt: RuntimeFunction| -> RVA {
                rt.begin_address
            })
            .collect();

        for rva in functions.iter() {
            debug!("runtime function: {:#x}", rva);
            // RUNTIME_FUNCTION.BeginAddress is often the start of a function, but not always.
            // its the start of a __try block.
            // ref: http://www.osronline.com/article.cfm%5earticle=469.htm
            //
            // so we can't blindly create a function here...
            //
            // we should make a final pass over all defined instructions,
            // and select those with no predecessors as functions.
            ws.make_insn(*rva)?;
            ws.analyze()?;
        }

        Ok(())
    }
}
