#![allow(clippy::upper_case_acronyms)]

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    ops::Not,
};

use anyhow::Result;
use log::{debug, error, warn};
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

fn is_jump(insn: &dis::zydis::DecodedInstruction) -> bool {
    matches!(
        insn.mnemonic,
        dis::zydis::Mnemonic::JB
            | dis::zydis::Mnemonic::JBE
            | dis::zydis::Mnemonic::JCXZ
            | dis::zydis::Mnemonic::JECXZ
            | dis::zydis::Mnemonic::JKNZD
            | dis::zydis::Mnemonic::JKZD
            | dis::zydis::Mnemonic::JL
            | dis::zydis::Mnemonic::JLE
            | dis::zydis::Mnemonic::JMP
            | dis::zydis::Mnemonic::JNB
            | dis::zydis::Mnemonic::JNBE
            | dis::zydis::Mnemonic::JNL
            | dis::zydis::Mnemonic::JNLE
            | dis::zydis::Mnemonic::JNO
            | dis::zydis::Mnemonic::JNP
            | dis::zydis::Mnemonic::JNS
            | dis::zydis::Mnemonic::JNZ
            | dis::zydis::Mnemonic::JO
            | dis::zydis::Mnemonic::JP
            | dis::zydis::Mnemonic::JRCXZ
            | dis::zydis::Mnemonic::JS
            | dis::zydis::Mnemonic::JZ
    )
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
        for op in dis::get_operands(insn) {
            if is_jump(insn) {
                continue;
            }

            if matches!(insn.mnemonic, dis::zydis::Mnemonic::CALL) {
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

            if n < 0x100 {
                // skip small numbers
                continue;
            }

            if n == 0xFFFFFFFF {
                // skip -1i32
                continue;
            }

            if n < 0x001_0000 && n % 0x1000 == 0 {
                // skip small page aligned numbers
                continue;
            }

            if n > u64::MAX - 0x1000 {
                // skip small negative numbers
                continue;
            }

            numbers.insert(n);
        }
    }

    // strings
    {
        for op in dis::get_operands(insn) {
            if is_jump(insn) {
                continue;
            }

            if matches!(insn.mnemonic, dis::zydis::Mnemonic::CALL) {
                continue;
            }

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
            for op in dis::get_operands(insn).take(1) {
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
                    if extern_.starts_with("__imp_") {
                        // unlinked object files may refer to subsequently linked/imported symbols
                        // via the prefix `__imp_`.
                        apis.insert(extern_.replace("__imp_", ""));
                    } else {
                        apis.insert(extern_.clone());
                    }
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
    #[allow(dead_code)]
    address: VA,

    features: Features,
}

type FunctionsFeatures = BTreeMap<VA, FunctionDescriptor>;

fn extract_workspace_features(ws: &dyn lancelot::workspace::Workspace) -> Result<FunctionsFeatures> {
    let descriptors = ws
        .analysis()
        .functions
        .iter()
        .filter_map(|(&va, md)| {
            if md.flags.intersects(lancelot::workspace::FunctionFlags::THUNK) {
                return None;
            }

            let name = ws.analysis().names.names_by_address.get(&va)?;

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

fn extract_buf_features(config: Box<dyn Configuration>, buf: &[u8]) -> Result<FunctionsFeatures> {
    let ws = workspace_from_bytes(config, buf)?;
    extract_workspace_features(&*ws)
}

struct BuildSettings {
    triplet:  String,
    compiler: String,
    library:  String,
    version:  String,
    profile:  String,
}

fn output_functions_features(build: &BuildSettings, path: &str, features: &FunctionsFeatures) -> Result<()> {
    for desc in features.values() {
        for v in desc.features.numbers.iter() {
            print!(
                "{},{},{},{},{},",
                build.triplet, build.compiler, build.library, build.version, build.profile
            );
            println!("{},{},number,0x{:08x}", path, desc.name, v);
        }

        for v in desc.features.apis.iter() {
            print!(
                "{},{},{},{},{},",
                build.triplet, build.compiler, build.library, build.version, build.profile
            );
            println!("{},{},api,{}", path, desc.name, v);
        }

        for v in desc.features.strings.iter() {
            print!(
                "{},{},{},{},{},",
                build.triplet, build.compiler, build.library, build.version, build.profile
            );
            println!("{},{},string,{}", path, desc.name, json!(v));
        }
    }

    Ok(())
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
        .arg(clap::Arg::new("triplet").required(true).index(1))
        .arg(clap::Arg::new("compiler").required(true).index(2))
        .arg(clap::Arg::new("library").required(true).index(3))
        .arg(clap::Arg::new("version").required(true).index(4))
        .arg(clap::Arg::new("profile").required(true).index(5))
        .arg(
            clap::Arg::new("input")
                .required(true)
                .index(6)
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

    let build = BuildSettings {
        triplet:  matches.value_of("triplet").unwrap().to_string(),
        compiler: matches.value_of("compiler").unwrap().to_string(),
        library:  matches.value_of("library").unwrap().to_string(),
        version:  matches.value_of("version").unwrap().to_string(),
        profile:  matches.value_of("profile").unwrap().to_string(),
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{:5}] {} {}",
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
        // ignore warnings like: workspace: unknown file format: magic: 00 00
        .filter(|metadata| !metadata.target().starts_with("lancelot::workspace"))
        .apply()
        .expect("failed to configure logging");

    let config = empty();

    let filename = matches.value_of("input").unwrap();

    let buf = util::read_file(filename)?;

    if buf.starts_with(b"MZ") || buf.starts_with(&[0x64, 0x86]) {
        // PE or COFF

        let features = extract_buf_features(config.clone(), &buf)?;

        println!("# triplet,compiler,library,version,profile,path,function,type,value");
        output_functions_features(&build, "/", &features)?;
    } else if buf.starts_with(b"!<arch>\n") {
        // archive file

        println!("# triplet,compiler,library,version,profile,path,function,type,value");
        let mut ar = ar::Archive::new(buf.as_slice());
        while let Some(entry_result) = ar.next_entry() {
            let mut entry = match entry_result {
                Ok(entry) => entry,
                Err(e) => {
                    warn!("failed to read archive entry: {:?}", e);
                    continue;
                }
            };

            let Ok(path) = String::from_utf8(entry.header().identifier().to_vec()) else {
                continue;
            };

            // fix paths to use forward slashes
            let path = path.replace('\\', "/");
            debug!("ar: path: {}", path);

            let mut sbuf = Vec::with_capacity(entry.header().size() as usize);
            entry.read_to_end(&mut sbuf)?;

            let features = match extract_buf_features(config.clone(), &sbuf) {
                Ok(features) => features,
                Err(e) => {
                    // MS may embed some files with COFF magic/machine == 00 00
                    // such as in libcmt.lib.
                    // object::coff doesn't parse these, so we skip them.
                    debug!("failed to extract features: {}: {}", path, e);
                    continue;
                }
            };

            output_functions_features(&build, &path, &features)?;
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

#[cfg(test)]
mod tests {
    use log::debug;
    use std::path::PathBuf;

    use super::*;

    /// Fetch the file system path of the given resource.
    fn get_path(name: &str) -> String {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("..");
        d.push("core");
        d.push("resources");
        d.push("test");
        d.push(name);
        println!("{}", String::from(d.to_str().unwrap()));
        String::from(d.to_str().unwrap())
    }

    /// Fetch the contents of the given resource.
    pub fn get_buf(name: &str) -> Vec<u8> {
        lancelot::util::read_file(&get_path(name)).unwrap()
    }

    fn ar_first_entry(buf: &[u8]) -> Result<Vec<u8>> {
        let mut ar = ar::Archive::new(buf);
        loop {
            let mut entry = ar.next_entry().unwrap().unwrap();

            let path = String::from_utf8(entry.header().identifier().to_vec()).unwrap();
            let path = path.replace('\\', "/");
            debug!("ar: path: {}", path);

            let mut sbuf = Vec::with_capacity(entry.header().size() as usize);
            entry.read_to_end(&mut sbuf)?;

            if &sbuf[..2] == b"\x00\x00" {
                continue;
            }
            return Ok(sbuf);
        }
    }

    #[test]
    fn coff_from_libcpmt() -> Result<()> {
        let buf = get_buf("libcpmt.lib");
        let config = lancelot::workspace::config::empty();
        let buf = ar_first_entry(buf.as_slice())?;
        let ws = workspace_from_bytes(config, &buf)?;

        assert_eq!(
            ws.analysis().names.addresses_by_name.first_key_value().unwrap().0,
            &"___std_init_once_begin_initialize_clr@16"
        );

        assert_eq!(
            ws.analysis().names.addresses_by_name["___std_init_once_begin_initialize_clr@16"],
            0x20000000
        );

        Ok(())
    }

    // duplicated from core/src/test.rs
    pub fn _init_logging() {
        let log_level = log::LevelFilter::Debug;
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
    }

    #[test]
    fn coff_from_libcmt() -> Result<()> {
        // libcmt.lib contains objects with Machine/magic == 00 00
        // that we'll want to skip gracefully.

        let buf = get_buf("libcmt.lib");
        let config = lancelot::workspace::config::empty();
        let buf = ar_first_entry(buf.as_slice())?;
        let ws = workspace_from_bytes(config, &buf)?;

        assert_eq!(
            ws.analysis().names.addresses_by_name.first_key_value().unwrap().0,
            &".data"
        );

        assert_eq!(ws.analysis().names.addresses_by_name[".data"], 0x20001000);

        Ok(())
    }

    #[test]
    fn coff_from_mfcm140() -> Result<()> {
        // MFCM140.lib contains objects with an unknown Symbol type
        // issue #182
        //init_logging();

        let buf = get_buf("MFCM140.lib");
        let config = lancelot::workspace::config::empty();
        let buf = ar_first_entry(buf.as_slice())?;
        let ws = workspace_from_bytes(config, &buf)?;

        assert_eq!(
            ws.analysis().names.addresses_by_name.first_key_value().unwrap().0,
            &".CRTMP$XCY"
        );

        assert_eq!(ws.analysis().names.addresses_by_name[".CRTMP$XCY"], 0x20016000);

        Ok(())
    }
}
