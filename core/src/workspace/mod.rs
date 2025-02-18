#![allow(clippy::borrowed_box)]

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Not,
};

use anyhow::Result;
use bitflags::bitflags;
use log::warn;
use thiserror::Error;

use crate::{
    analysis::{
        cfg::{flow::Flow, InstructionIndex, CFG},
        pe::{Import, ImportedSymbol},
    },
    loader::{
        coff::{SymbolKind, COFF},
        pe::PE,
    },
    module::Module,
    VA,
};

pub mod config;
pub mod export;
pub mod formatter;

#[derive(Error, Debug)]
pub enum WorkspaceError {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("format not supported")]
    FormatNotSupported {
        // we want the following:
        //
        // #[backtrace]
        //
        // but this requires nightly for Rust 1.73+.
        // see: https://github.com/rust-lang/rust/issues/99301
        source: anyhow::Error,
    },
}

bitflags! {
    pub struct FunctionFlags: u8 {
        const NORET = 0b0000_0001;
        const THUNK = 0b0000_0010;
    }
}

#[derive(Clone, Copy)]
pub struct FunctionAnalysis {
    pub flags: FunctionFlags,
}

#[derive(Default)]
pub struct NameIndex {
    pub names_by_address:  BTreeMap<VA, String>,
    pub addresses_by_name: BTreeMap<String, VA>,
}

impl NameIndex {
    pub fn insert(&mut self, va: VA, name: String) {
        self.names_by_address.insert(va, name.clone());
        self.addresses_by_name.insert(name, va);
    }

    pub fn contains_address(&self, va: VA) -> bool {
        self.names_by_address.contains_key(&va)
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.addresses_by_name.contains_key(name)
    }
}

pub struct WorkspaceAnalysis {
    // derived from:
    //   - file format analysis passes
    //   - cfg flow analysis (call insns)
    //   - manual actions
    pub functions: BTreeMap<VA, FunctionAnalysis>,

    // derived from:
    //   - file format analysis pass: pe::get_imports()
    pub imports: BTreeMap<VA, Import>,

    pub externs: BTreeMap<VA, String>,

    // derived from:
    //  - user names
    //  - export names
    //  - imported symbols
    //  - flirt sigs
    pub names: NameIndex,
}

pub trait Workspace: Send {
    fn config(&self) -> &Box<dyn config::Configuration>;
    fn cfg(&self) -> &CFG;
    fn analysis(&self) -> &WorkspaceAnalysis;
    fn module(&self) -> &Module;
}

pub struct PEWorkspace {
    pub config:   Box<dyn config::Configuration>,
    pub pe:       PE,
    pub cfg:      CFG,
    pub analysis: WorkspaceAnalysis,
}

impl PEWorkspace {
    pub fn from_pe(config: Box<dyn config::Configuration>, pe: PE) -> Result<PEWorkspace> {
        let mut insns: InstructionIndex = Default::default();
        let mut function_starts: BTreeSet<VA> = Default::default();

        function_starts.extend(config.get_function_hints()?);

        function_starts.extend(crate::analysis::pe::find_function_starts(&pe)?);

        for &function in function_starts.iter() {
            insns.build_index(&pe.module, function)?;
        }

        // heuristic that we trust:
        //   - find_new_code_references: existing instruction operands that reference
        //     likely code.

        loop {
            let new_code = crate::analysis::cfg::code_references::find_new_code_references(&pe.module, &insns)?;
            if new_code.is_empty() {
                break;
            }

            for &function in new_code.iter() {
                insns.build_index(&pe.module, function)?;

                function_starts.insert(function);
                // is this the right thing to do? are these guaranteed to be
                // functions? we can imagine SEH handlers being
                // referenced. so: no. probably the users of the
                // workspace will want to enumerate CFG "roots", rather than
                // functions. but then, what about tail calls,
                // where a function has a jump to it, therefore not a root?
                // this is another discussion that probably shouldn't be inline
                // here.
            }
        }

        let mut cfg = CFG::from_instructions(&pe.module, insns)?;

        let mut noret = crate::analysis::pe::noret_imports::cfg_prune_noret_imports(&pe, &mut cfg)?;

        let mut function_starts = function_starts
            .into_iter()
            .filter(|va| cfg.insns.insns_by_address.contains_key(va))
            .collect::<BTreeSet<VA>>();
        let call_targets = cfg
            .basic_blocks
            .blocks_by_address
            .keys()
            .cloned()
            .filter(|bb| {
                cfg.flows.flows_by_dst[bb]
                    .iter()
                    .any(|flow| matches!(flow, Flow::Call(_)))
            })
            .collect::<BTreeSet<VA>>();
        function_starts.extend(call_targets);

        let imports = crate::analysis::pe::get_imports(&pe)?;

        let mut names: NameIndex = Default::default();
        for import in imports.values() {
            let name = match &import.symbol {
                ImportedSymbol::Name(name) => format!("{}!{}", import.dll, name),
                ImportedSymbol::Ordinal(ordinal) => format!("{}!#{}", import.dll, ordinal),
            };

            names.insert(import.address, name);
        }

        let sigs = config.get_sigs()?;
        for &function in function_starts.iter() {
            let matches = crate::analysis::flirt::match_flirt(&pe.module, &sigs, function)?;

            match matches.len().cmp(&1) {
                std::cmp::Ordering::Less => {
                    // no matches
                    continue;
                }
                std::cmp::Ordering::Equal => {
                    // exactly one match: perfect.
                    if let Some(name) = matches[0].get_name() {
                        log::info!("FLIRT match: {:#x}: {}", function, name);
                        names.insert(function, name.to_string());
                    } else {
                        // no associated name, just know its a library function
                        continue;
                    }
                }
                std::cmp::Ordering::Greater => {
                    // colliding matches, can't determine the name.
                    // TODO: maybe check for special case that all names are the same?
                    log::info!("FLIRT match: {:#x}: {} collisions", function, matches.len());
                    continue;
                }
            }
        }

        for name in [
            "kernel32.dll!ExitProcess",
            "kernel32.dll!ExitThread",
            "exit",
            "_exit",
            "__exit",
            "__amsg_exit",
        ] {
            if let Some(&va) = names.addresses_by_name.get(name) {
                log::info!("noret via name: {}: {:#x}", name, va);
                noret.extend(crate::analysis::cfg::noret::cfg_mark_noret(&pe.module, &mut cfg, va)?);
            }
        }

        let thunks = crate::analysis::cfg::thunk::find_thunks(&cfg, function_starts.iter());

        let mut functions: BTreeMap<VA, FunctionAnalysis> = Default::default();
        for va in function_starts {
            let mut flags = FunctionFlags::empty();

            if noret.contains(&va) {
                flags.set(FunctionFlags::NORET, true);
            }

            if thunks.contains(&va) {
                flags.set(FunctionFlags::THUNK, true);
            }

            functions.insert(va, FunctionAnalysis { flags });
        }

        for &function in functions.keys() {
            if names.contains_address(function).not() {
                names.insert(function, format!("sub_{function:x}"));
            }
        }

        Ok(PEWorkspace {
            config,
            pe,
            cfg,
            analysis: WorkspaceAnalysis {
                functions,
                imports,
                externs: Default::default(),
                names,
            },
        })
    }
}

impl Workspace for PEWorkspace {
    fn config(&self) -> &Box<dyn config::Configuration> {
        &self.config
    }

    fn cfg(&self) -> &CFG {
        &self.cfg
    }

    fn analysis(&self) -> &WorkspaceAnalysis {
        &self.analysis
    }

    fn module(&self) -> &Module {
        &self.pe.module
    }
}

pub struct COFFWorkspace {
    pub config:   Box<dyn config::Configuration>,
    pub coff:     COFF,
    pub cfg:      CFG,
    pub analysis: WorkspaceAnalysis,
}

impl COFFWorkspace {
    pub fn from_coff(config: Box<dyn config::Configuration>, coff: COFF) -> Result<COFFWorkspace> {
        let mut insns: InstructionIndex = Default::default();
        let mut function_starts: BTreeSet<VA> = Default::default();

        function_starts.extend(config.get_function_hints()?);

        let mut names: NameIndex = Default::default();
        for (name, symbol) in coff.symbols.by_name.iter() {
            if let SymbolKind::Text = symbol.kind {
                function_starts.insert(symbol.address);
                names.insert(symbol.address, name.clone());
            }
        }
        // each address may have multiple associated names.
        // so prefer function names, and then fill  in anything else.
        for (name, symbol) in coff.symbols.by_name.iter() {
            if names.contains_address(symbol.address).not() {
                names.insert(symbol.address, name.clone());
            }
        }

        let externs: BTreeMap<VA, String> = coff.externs.iter().map(|(name, &va)| (va, name.clone())).collect();
        for (&va, name) in externs.iter() {
            names.insert(va, name.clone());
        }

        for &function in function_starts.iter() {
            insns.build_index(&coff.module, function)?;
        }

        loop {
            let new_code = crate::analysis::cfg::code_references::find_new_code_references(&coff.module, &insns)?;
            if new_code.is_empty() {
                break;
            }

            for &function in new_code.iter() {
                insns.build_index(&coff.module, function)?;

                // see note in PE workspace about whether this is the right idea or note.
                function_starts.insert(function);
            }
        }

        let mut cfg = CFG::from_instructions(&coff.module, insns)?;

        let mut function_starts = function_starts
            .into_iter()
            .filter(|va| cfg.insns.insns_by_address.contains_key(va))
            .collect::<BTreeSet<VA>>();
        let call_targets = cfg
            .basic_blocks
            .blocks_by_address
            .keys()
            .cloned()
            .filter(|bb| {
                cfg.flows.flows_by_dst[bb]
                    .iter()
                    .any(|flow| matches!(flow, Flow::Call(_)))
            })
            .collect::<BTreeSet<VA>>();
        function_starts.extend(call_targets);

        let mut noret: BTreeSet<VA> = Default::default();

        for name in [
            "kernel32.dll!ExitProcess",
            "kernel32.dll!ExitThread",
            "exit",
            "_exit",
            "__exit",
            "__amsg_exit",
        ] {
            if let Some(&va) = names.addresses_by_name.get(name) {
                log::info!("noret via name: {}: {:#x}", name, va);
                noret.extend(crate::analysis::cfg::noret::cfg_mark_noret(&coff.module, &mut cfg, va)?);
            }
        }

        let thunks = crate::analysis::cfg::thunk::find_thunks(&cfg, function_starts.iter());

        let mut functions: BTreeMap<VA, FunctionAnalysis> = Default::default();
        for va in function_starts {
            let mut flags = FunctionFlags::empty();

            if noret.contains(&va) {
                flags.set(FunctionFlags::NORET, true);
            }

            if thunks.contains(&va) {
                flags.set(FunctionFlags::THUNK, true);
            }

            functions.insert(va, FunctionAnalysis { flags });
        }

        for &function in functions.keys() {
            if names.contains_address(function).not() {
                names.insert(function, format!("sub_{function:x}"));
            }
        }

        Ok(COFFWorkspace {
            config,
            coff,
            cfg,
            analysis: WorkspaceAnalysis {
                functions,
                imports: Default::default(),
                externs,
                names,
            },
        })
    }
}

impl Workspace for COFFWorkspace {
    fn config(&self) -> &Box<dyn config::Configuration> {
        &self.config
    }

    fn cfg(&self) -> &CFG {
        &self.cfg
    }

    fn analysis(&self) -> &WorkspaceAnalysis {
        &self.analysis
    }

    fn module(&self) -> &Module {
        &self.coff.module
    }
}

pub fn workspace_from_bytes(config: Box<dyn config::Configuration>, buf: &[u8]) -> Result<Box<dyn Workspace>> {
    if buf.len() < 2 {
        return Err(WorkspaceError::BufferTooSmall.into());
    }

    // TODO: move this tasting to the loaders?
    match (buf[1] as u16) << 8u16 | buf[0] as u16 {
        0x5A4D => {
            let pe = crate::loader::pe::PE::from_bytes(buf)?;
            Ok(Box::new(PEWorkspace::from_pe(config, pe)?))
        }
        0x14C => {
            // coff.Machine == IMAGE_FILE_MACHINE_I386
            // from msvcrt libcpmt.lib 0a783ea78e08268f9ead780da0368409
            let coff = crate::loader::coff::COFF::from_bytes(buf)?;
            Ok(Box::new(COFFWorkspace::from_coff(config, coff)?))
        }
        0x8664 => {
            // coff.Machine == IMAGE_FILE_MACHINE_AMD64
            // from static libs built via MSVC 2019
            let coff = crate::loader::coff::COFF::from_bytes(buf)?;
            Ok(Box::new(COFFWorkspace::from_coff(config, coff)?))
        }
        _ => {
            warn!("workspace: unknown file format: magic: {:02x} {:02x}", buf[0], buf[1]);
            Err(WorkspaceError::FormatNotSupported {
                source: anyhow::anyhow!("unknown magic"),
            }
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsrc::*;

    #[test]
    fn nop() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let config = get_config();

        let ws = PEWorkspace::from_pe(config, pe)?;

        // entry point
        assert!(ws.analysis.functions.contains_key(&0x401081));

        // main
        assert!(ws.analysis.functions.contains_key(&0x401000));

        assert!(ws.analysis.imports.contains_key(&0x40600C));
        assert!(ws
            .analysis
            .names
            .contains_name(&String::from("kernel32.dll!ExitProcess")));
        assert!(ws.analysis.names.contains_address(0x40600C));

        // 0x401C4E: void __cdecl __noreturn __crtExitProcess(UINT uExitCode)
        assert!(ws.analysis.functions[&0x401C4E].flags.intersects(FunctionFlags::NORET));

        // ```
        //     .text:00405F42  ; void __stdcall RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
        //     .text:00405F42  RtlUnwind       proc near               ; CODE XREF: __global_unwind2+13↑p
        //     .text:00405F42
        //     .text:00405F42  TargetFrame     = dword ptr  4
        //     .text:00405F42  TargetIp        = dword ptr  8
        //     .text:00405F42  ExceptionRecord = dword ptr  0Ch
        //     .text:00405F42  ReturnValue     = dword ptr  10h
        //     .text:00405F42
        //     .text:00405F42 000 FF 25 7C 60 40 00  jmp     ds:__imp_RtlUnwind
        //     .text:00405F42  RtlUnwind       endp
        // ```
        assert!(ws.analysis.functions[&0x405F42].flags.intersects(FunctionFlags::THUNK));

        // via FLIRT 0x401da9: _exit
        assert!(ws.analysis.functions.contains_key(&0x401da9));
        assert!(ws.analysis.names.contains_name(&String::from("_exit")));
        assert!(ws.analysis.functions[&0x401da9].flags.intersects(FunctionFlags::NORET));

        Ok(())
    }

    #[test]
    fn pe() -> Result<()> {
        let buf = get_buf(Rsrc::NOP);
        let config = get_config();
        let ws = workspace_from_bytes(config, &buf)?;

        assert!(ws.analysis().functions.contains_key(&0x401081));

        Ok(())
    }

    #[test]
    fn coff() -> Result<()> {
        let buf = get_buf(Rsrc::ALTSVC);
        let config = get_config();
        let ws = workspace_from_bytes(config, &buf)?;

        assert_eq!(
            ws.analysis().names.addresses_by_name.get("Curl_alpnid2str").unwrap(),
            &0x2000_0000u64
        );

        Ok(())
    }

    #[test]
    fn ws_thunks() -> Result<()> {
        //crate::test::init_logging();

        let buf = get_buf(Rsrc::CPP1);
        let config = get_config();
        let ws = workspace_from_bytes(config, &buf)?;

        let expected = [
            0x140011005,
            0x14001100a,
            0x14001100f,
            0x140011028,
            0x14001102d,
            0x140011046,
            0x14001104b,
            0x140011050,
            0x140011055,
            0x14001105a,
            0x14001105f,
            0x140011064,
            0x140011069,
            0x14001106e,
            0x140011073,
            0x140011078,
            0x140011082,
            0x140011087,
            0x140011091,
            0x140011096,
            0x1400110a0,
            0x1400110af,
            0x1400110b4,
            0x1400110be,
            0x1400110c8,
            0x1400110cd,
            0x1400110d7,
            0x1400110dc,
            0x1400110e1,
            0x1400110e6,
            0x1400110fa,
            0x140011104,
            0x140011118,
            0x140011122,
            0x140011127,
            0x14001112c,
            0x140011136,
            0x140011145,
            0x14001114f,
            0x140011154,
            0x140011159,
            0x14001115e,
            0x140011168,
            0x140011177,
            0x14001117c,
            0x140011181,
            0x14001119a,
            0x14001119f,
            0x1400111a9,
            0x1400111ae,
            0x1400111b8,
            0x1400111c2,
            0x1400111c7,
            0x1400111cc,
            0x1400111d1,
            0x1400111db,
            0x1400111e5,
            0x1400111ea,
            0x1400111f4,
            0x14001120d,
            0x140011212,
            0x140011217,
            0x14001121c,
            0x140011221,
            0x14001122b,
            0x140011230,
            0x14001123a,
            0x14001123f,
            0x140011244,
            0x140011249,
            0x14001124e,
            0x140011262,
            0x14001126c,
            0x140011271,
            0x14001127b,
            0x140011280,
            0x140011294,
            0x14001129e,
            0x1400112a3,
            0x1400112a8,
            0x1400112ad,
            0x1400112b7,
            0x1400112bc,
            0x1400112c6,
            0x1400112cb,
            0x1400112d5,
            0x1400112da,
            0x1400112e4,
            0x1400112e9,
            0x1400112f8,
            0x14001130c,
            0x140011307,
            0x14001131b,
            0x140011320,
            0x140011325,
            0x14001132a,
            0x14001132f,
            0x140011339,
            0x140011343,
            0x140011348,
            0x14001134d,
            0x140011352,
            0x140011366,
            0x140011370,
            0x140011375,
            0x14001137a,
            0x140011389,
            0x14001138e,
            0x1400113ac,
            0x1400113b1,
            0x1400113b6,
            0x1400113c0,
            0x1400113c5,
            0x1400113ca,
            0x1400113cf,
            0x1400113d9,
            0x1400113de,
            0x1400113e8,
            0x1400113ed,
            0x1400113f2,
            0x1400113fc,
            0x140011401,
            0x140011406,
            0x14001140b,
            0x140011415,
            0x14001141a,
            0x14001141f,
            0x140011424,
            0x140011429,
            0x14001143d,
            0x14001144c,
            0x140011460,
            0x140011465,
            0x14001146f,
            0x140011474,
            0x140011479,
            0x14001147e,
            0x140011483,
            0x140011488,
            0x140011492,
            0x1400121f0,
            0x140012f91,
            0x1400157f0,
            0x1400157f6,
            0x1400157fc,
            0x140015802,
            0x140015808,
            0x14001580e,
            0x140015814,
            0x14001581a,
            0x140015820,
            0x140015826,
            0x14001582c,
            0x140015832,
            0x140015838,
            0x14001583e,
            0x140015844,
            0x14001584a,
            0x140015850,
            0x140015856,
            0x14001585c,
            0x140015862,
            0x140015868,
            0x14001586e,
            0x140015874,
            0x14001587a,
            0x140015880,
            0x140015886,
            0x14001588c,
            0x140015892,
            0x140015898,
            0x14001589e,
            0x1400158a4,
            0x1400158aa,
            0x1400158b0,
            0x1400158fe,
        ];

        for e in expected.iter() {
            assert!(
                ws.analysis().functions[e].flags.intersects(FunctionFlags::THUNK),
                "expected thunk not present: 0x{e:x}"
            );
        }

        for (function, analysis) in ws.analysis().functions.iter() {
            if analysis.flags.intersects(FunctionFlags::THUNK) {
                assert!(expected.contains(function), "extra thunk found: 0x{function:x}");
            }
        }

        assert!(
            ws.analysis().functions.contains_key(&0x140011CCC),
            "missing function: sub_140011CCC"
        );
        assert!(
            ws.analysis().functions.contains_key(&0x140014A30),
            "missing function: __scrt_unhandled_exception_filter"
        );

        Ok(())
    }
}
