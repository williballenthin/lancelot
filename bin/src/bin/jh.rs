#![allow(clippy::upper_case_acronyms)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    ops::Not,
};

use anyhow::Result;
use log::error;
use serde_json::json;

use lancelot::{
    analysis::dis::{self, get_first_operand, get_operand_xref},
    aspace::AddressSpace,
    module::Permissions,
    util,
    workspace::{
        config::{empty, Configuration},
        workspace_from_bytes,
    },
    RVA, VA,
};

struct Features {
    strings: BTreeSet<String>,
    numbers: BTreeSet<u64>,
    apis:    BTreeSet<String>,
}

fn extract_insn_features(
    ws: &dyn lancelot::workspace::Workspace,
    insn: &dis::zydis::DecodedInstruction,
    va: VA,
) -> Result<Features> {
    let mut strings: BTreeSet<String> = Default::default();
    let mut numbers: BTreeSet<u64> = Default::default();
    let mut apis: BTreeSet<String> = Default::default();

    // numbers
    {
        for op in insn
            .operands
            .iter()
            .filter(|op| op.visibility == dis::zydis::OperandVisibility::EXPLICIT)
            .take(3)
        {
            if matches!(insn.mnemonic, dis::zydis::Mnemonic::JMP | dis::zydis::Mnemonic::CALL) {
                continue;
            }

            let n = match op.ty {
                dis::zydis::OperandType::IMMEDIATE => op.imm.value,
                // maybe also consider: dis::zydis::OperandType::MEMORY => {
                _ => continue,
            };

            if ws.module().probe_va(n, Permissions::R) {
                // this is a valid address, so assume its not a constant.
                continue;
            }

            let op0 = get_first_operand(insn).expect("no operands");

            if matches!(insn.mnemonic, dis::zydis::Mnemonic::ADD)
                && matches!(op0.ty, dis::zydis::OperandType::REGISTER)
                && matches!(op0.reg, dis::zydis::Register::RSP | dis::zydis::Register::ESP)
            {
                // skip function epilog.
                // skip things like:
                //
                //     .text:00401140                 call    sub_407E2B
                //     .text:00401145                 add     esp, 0Ch
                continue;
            }

            if matches!(insn.mnemonic, dis::zydis::Mnemonic::SUB)
                && matches!(op0.ty, dis::zydis::OperandType::REGISTER)
                && matches!(op0.reg, dis::zydis::Register::RSP | dis::zydis::Register::ESP)
            {
                // skip function prolog.
                continue;
            }

            if n < 0x1000 {
                // skip small numbers
                continue;
            }

            if n > u64::MAX - 0x1_0000 {
                // skip small negative numbers
                continue;
            }

            numbers.insert(n);
        }
    }

    // strings
    {
        for op in insn
            .operands
            .iter()
            .filter(|op| op.visibility == dis::zydis::OperandVisibility::EXPLICIT)
            .take(3)
        {
            let x = match get_operand_xref(ws.module(), va, insn, op) {
                Err(_) => continue,
                Ok(None) => continue,
                Ok(Some(dis::Target::Indirect(ptr))) => ptr,
                Ok(Some(dis::Target::Direct(va))) => va,
            };

            if ws.module().probe_va(x, Permissions::R).not() {
                continue;
            }

            if let Ok(s) = ws.module().address_space.read_ascii(x, 4) {
                strings.insert(s);
            } else {
                // try to dereference at the address and read a string from there.
                // only follow one level of indirection.
                let Ok(ptr) = ws.module().read_va_at_va(x) else {
                    continue;
                };

                if let Ok(s) = ws.module().address_space.read_ascii(ptr, 4) {
                    strings.insert(s);
                }
            }
        }
    }

    // APIs
    {
        // JMP for tail calls
        if matches!(insn.mnemonic, dis::zydis::Mnemonic::CALL | dis::zydis::Mnemonic::JMP) {
            for op in insn
                .operands
                .iter()
                .filter(|op| op.visibility == dis::zydis::OperandVisibility::EXPLICIT)
                .take(1)
            {
                let x = match get_operand_xref(ws.module(), va, insn, op) {
                    Err(_) => continue,
                    Ok(None) => continue,
                    Ok(Some(dis::Target::Indirect(ptr))) => ptr,
                    Ok(Some(dis::Target::Direct(va))) => va,
                };

                if let Some(import) = ws.analysis().imports.get(&x) {
                    if let lancelot::analysis::pe::ImportedSymbol::Name(name) = &import.symbol {
                        let name = format!("{}!{}", import.dll, name);
                        apis.insert(name);
                    }
                }

                if let Some(extern_) = ws.analysis().externs.get(&x) {
                    apis.insert(extern_.clone());
                }

                // local function with a name, such as recovered via symbols or FLIRT
                if ws.analysis().functions.contains_key(&x) {
                    if let Some(name) = ws.analysis().names.names_by_address.get(&x) {
                        if name.starts_with("sub_") {
                            // skip auto-generated names.
                            // hacky, but works for now.
                            continue;
                        }

                        apis.insert(name.clone());
                    }
                }
            }
        }
    }

    Ok(Features { strings, numbers, apis })
}

fn extract_function_features(ws: &dyn lancelot::workspace::Workspace, va: VA) -> Result<Features> {
    let mut strings: BTreeSet<String> = Default::default();
    let mut numbers: BTreeSet<u64> = Default::default();
    let mut apis: BTreeSet<String> = Default::default();

    let mut blocks = ws.cfg().get_reachable_blocks(va).collect::<Vec<_>>();
    blocks.sort_unstable_by_key(|&bb| bb.address);

    let decoder = dis::get_disassembler(ws.module()).unwrap();

    for bb in blocks.into_iter() {
        // need to over-read the bb buffer, to account for the final instructions.
        let buf = ws
            .module()
            .address_space
            .read_bytes(bb.address, bb.length as usize + 0x10)?;

        for (offset, insn) in dis::linear_disassemble(&decoder, &buf) {
            // because we over-read the bb buffer,
            // discard the instructions found after it.
            if offset >= bb.length as usize {
                break;
            }

            if let Ok(Some(insn)) = insn {
                let va = bb.address + offset as RVA;

                let ifeatures = extract_insn_features(ws, &insn, va)?;

                strings.extend(ifeatures.strings);
                numbers.extend(ifeatures.numbers);
                apis.extend(ifeatures.apis);
            }
        }
    }

    Ok(Features { strings, numbers, apis })
}

struct FunctionDescriptor {
    name:    String,
    address: VA,

    features: Features,
}

fn extract_workspace_features(ws: &dyn lancelot::workspace::Workspace) -> Result<BTreeMap<VA, FunctionDescriptor>> {
    let descriptors = ws
        .analysis()
        .functions
        .iter()
        .filter_map(|(&va, md)| {
            if md.flags.intersects(lancelot::workspace::FunctionFlags::THUNK) {
                return None;
            }

            let Some(name) = ws.analysis().names.names_by_address.get(&va) else {
                return None;
            };

            let Ok(features) = extract_function_features(ws, va) else {
                return None;
            };

            Some((
                va,
                FunctionDescriptor {
                    name: name.to_string(),
                    address: va,
                    features,
                },
            ))
        })
        .collect::<BTreeMap<VA, FunctionDescriptor>>();

    Ok(descriptors)
}

fn extract_buf_features(config: Box<dyn Configuration>, buf: &[u8]) -> Result<BTreeMap<VA, FunctionDescriptor>> {
    let ws = workspace_from_bytes(config, buf)?;
    extract_workspace_features(&*ws)
}

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::App::new("jh")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("extract interesting features from functions")
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .multiple_occurrences(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("disable informational messages"),
        )
        .arg(
            clap::Arg::new("input")
                .required(true)
                .index(1)
                .help("path to file to analyze"),
        )
        .get_matches();

    // --quiet overrides --verbose
    let log_level = if matches.is_present("quiet") {
        log::LevelFilter::Error
    } else {
        match matches.occurrences_of("verbose") {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            2 => log::LevelFilter::Trace,
            _ => log::LevelFilter::Trace,
        }
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {
                    record.target()
                } else {
                    ""
                },
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .filter(|metadata| !metadata.target().starts_with("goblin::pe"))
        .apply()
        .expect("failed to configure logging");

    let config = empty();

    let filename = matches.value_of("input").unwrap();

    let buf = util::read_file(filename)?;

    if buf.starts_with(b"!<arch>\n") {
        // archive file

        let mut ar = ar::Archive::new(buf.as_slice());
        while let Some(entry_result) = ar.next_entry() {
            let Ok(mut entry) = entry_result else {
                continue;
            };

            let Ok(name) = String::from_utf8(entry.header().identifier().to_vec()) else {
                continue;
            };

            let mut sbuf = Vec::with_capacity(entry.header().size() as usize);
            entry.read_to_end(&mut sbuf)?;

            println!("{}", name);

            for desc in extract_buf_features(config.clone(), &sbuf)?.values() {
                println!("  function: {} (0x{:08x})", desc.name, desc.address);

                for v in desc.features.numbers.iter() {
                    println!("    number: 0x{:08x}", v);
                }

                for v in desc.features.strings.iter() {
                    println!("    string: {}", json!(v));
                }

                for v in desc.features.apis.iter() {
                    println!("    api: {}", v);
                }
            }
        }
    } else if buf.starts_with(b"MZ") || buf.starts_with(&[0x64, 0x86]) {
        // PE or COFF
        for desc in extract_buf_features(config, &buf)?.values() {
            println!("function: {} (0x{:08x})", desc.name, desc.address);

            for v in desc.features.numbers.iter() {
                println!("  number: 0x{:08x}", v);
            }

            for v in desc.features.strings.iter() {
                println!("  string: {}", json!(v));
            }

            for v in desc.features.apis.iter() {
                println!("  api: {}", v);
            }
        }
    } else {
        error!("unrecognized file format");
        return Ok(());
    }

    Ok(())
}

fn main() {
    if let Err(e) = _main() {
        #[cfg(debug_assertions)]
        error!("{:?}", e);
        #[cfg(not(debug_assertions))]
        error!("{:}", e);
    }
}
