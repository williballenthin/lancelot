use num::{FromPrimitive, ToPrimitive};
use std::marker::PhantomData;
use std::collections::HashSet;

use log::{debug, info};
use goblin::{Object};
use failure::{Error};

use super::super::super::arch::Arch;
use super::super::super::loader::{Permissions};
use super::super::super::workspace::Workspace;
use super::super::{Analyzer, AnalysisError};


pub struct PtrAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> PtrAnalyzer<A> {
    pub fn new() -> PtrAnalyzer<A> {
        PtrAnalyzer {
            _phantom: PhantomData {},
        }
    }
}

struct Section<A: Arch> {
    start: A::RVA,
    end: A::RVA,
}

fn is_in_insn<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> bool {
    let start: usize = rva.to_usize().unwrap();
    // TODO: remove harded max insn length
    // TODO: underflow
    let end: usize = rva.to_usize().unwrap() - 0x10;

    for i in (start..end).rev() {
        let i = A::RVA::from_usize(i).unwrap();
        if let Some(meta) = ws.get_meta(i) {
            if !meta.is_insn() {
                continue;
            }

            if let Ok(len) = meta.get_insn_length() {
                if i + A::RVA::from_u8(len).unwrap() > rva {
                    return true;
                }
            }
        }
    }
    return false;
}

fn is_ptr<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> bool {
    if let Ok(ptr) = ws.read_va(rva) {
        if let Some(ptr) = ws.rva(ptr) {
            return ws.probe(ptr, 1);
        }
    }
    return false;
}

impl<A: Arch + 'static> Analyzer<A> for PtrAnalyzer<A> {
    fn get_name(&self) -> String {
        "pointer analyzer".to_string()
    }

    fn analyze(&self, ws: &mut Workspace<A>)-> Result<(), Error> {
        let pe = match Object::parse(&ws.buf) {
            Ok(Object::PE(pe)) => pe,
            _ => panic!("can't analyze unexpected format"),
        };

        let text_section = match ws.module.sections.iter()
            .filter(|&sec| sec.name == ".text")
            .next() {
                None => return Ok(()),
                Some(s) => s,
            };

        info!("found text section");

        let text_bounds = Section::<A> {
            start: text_section.addr,
            end: text_section.addr + A::RVA::from_usize(text_section.buf.len()).unwrap(),
        };

        let start: usize = text_bounds.start.to_usize().unwrap();
        let end: usize = text_bounds.end.to_usize().unwrap();

        let o: HashSet<A::RVA> = (start..end)
            .filter_map(|rva| A::RVA::from_usize(rva))
            .map(|rva| ws.read_va(rva))
            .filter_map(Result::ok)
            .filter_map(|va| ws.rva(va))
            .filter(|&rva| text_bounds.start <= rva)
            .filter(|&rva| rva < text_bounds.end)
            .filter(|&rva| !is_in_insn(ws, rva))
            .filter(|&rva| !is_ptr(ws, rva))
            .collect();

        o.iter().for_each(|&rva| {
            info!("found ptr from .text section to .text section at {:#x}", rva);
            ws.make_insn(rva);
            // TODO: consume result
            ws.analyze().unwrap();
        });
        Ok(())
    }
}
