use num::{FromPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};
use byteorder::{ByteOrder, LittleEndian};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct RuntimeFunctionAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> RuntimeFunctionAnalyzer<A> {
    pub fn new() -> RuntimeFunctionAnalyzer<A> {
        RuntimeFunctionAnalyzer {
            _phantom: PhantomData {},
        }
    }
}


struct RuntimeFunction<A: Arch> {
    begin_address: A::RVA,
    end_address: A::RVA,
    unwind_data: A::RVA,
}


impl<A: Arch> std::fmt::Debug for RuntimeFunction<A>{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RUNTIME_FUNCTION(begin: {:#x} end: {:#x} data: {:#x})",
               self.begin_address,
               self.end_address,
               self.unwind_data
        )
    }
}


impl<A: Arch + 'static> Analyzer<A> for RuntimeFunctionAnalyzer<A> {
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
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = RuntimeFunctionAnalyzer::<Arch64>::new();
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
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
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

            (A::RVA::from_u32(exception_directory.virtual_address).unwrap(), exception_directory.size)
        };

        debug!("exception directory: {:#x}", exception_directory);

        let buf = ws.read_bytes(exception_directory, directory_size as usize)?;
        let functions: Vec<A::RVA> = buf
            .chunks_exact(3 * 4)
            .map(|b| RuntimeFunction{
                begin_address: A::RVA::from_u32(LittleEndian::read_u32(b)).unwrap(),
                end_address: A::RVA::from_u32(LittleEndian::read_u32(&b[4..])).unwrap(),
                unwind_data: A::RVA::from_u32(LittleEndian::read_u32(&b[8..])).unwrap(),
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
            .map(|rt: RuntimeFunction<A>| -> A::RVA {
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
