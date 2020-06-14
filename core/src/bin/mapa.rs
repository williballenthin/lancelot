// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// TODO: imports
// TODO: resources
// TODO: overlay
// TODO: stack strings
// TODO: function names
// TODO: flirt function names

use std::collections::BTreeMap;

use anyhow::Result;
use log::{debug, error};
#[macro_use]
extern crate clap;
#[macro_use]
extern crate anyhow;

use lancelot::{
    aspace::AddressSpace,
    loader::pe::{
        imports::{get_import_directory, read_import_descriptors, read_thunks, IMAGE_THUNK_DATA},
        load_pe, PE,
    },
    util, RVA, VA,
};

#[derive(Debug)]
enum Structure {
    /// the complete file
    File,
    /// the file headers.
    Header,
    IMAGE_DOS_HEADER,
    IMAGE_NT_HEADERS,
    Signature,
    IMAGE_FILE_HEADER,
    IMAGE_OPTIONAL_HEADER,
    IMAGE_SECTION_HEADER(u16, String),
    /// a section's content
    Section(u16, String),
    ImportTable,
    ExportTable,
    ResourceTable,
    ExceptionTable,
    CertificateTable,
    BaseRelocationTable,
    DebugData,
    TlsTable,
    LoadConfigTable,
    BoundImportTable,
    DelayImportDescriptor,
    ClrRuntimeHeader,
    String(String),
    Function(String),
}

#[derive(Debug)]
struct Range {
    start:     VA,
    end:       VA,
    structure: Structure,
}

#[derive(Default)]
struct Ranges {
    map: BTreeMap<(VA, i64), Range>,
}

impl Ranges {
    fn insert(&mut self, start: VA, end: VA, structure: Structure) -> Result<()> {
        if end > i64::MAX as u64 {
            return Err(anyhow!("address too large (>= i64::MAX)"));
        }

        let key = (start, -(end as i64));
        let range = Range { start, end, structure };

        self.map.insert(key, range);

        Ok(())
    }

    fn root(&self) -> Result<&Range> {
        Ok(self.map.values().next().unwrap())
    }

    /// find ranges that fall within the given range.
    /// only collect the ranges that are direct children of the range.
    fn get_children<'a>(&self, range: &'a Range) -> Result<Vec<&Range>> {
        let key = (range.start, -(range.end as i64));
        let max = (u64::MAX, i64::MIN);

        // assume the PE is not mapped at 0x0
        // otherwise, we'll miss the first range.
        if range.start == 0x0 {
            panic!("module cannot be mapped at 0x0, yet");
        }
        // covered is the last address yielded so far.
        // once we yield a direct child, we don't want to yield its children.
        let mut covered = 0x0;

        let mut children = vec![];
        for (_, child) in self
            .map
            .range((std::ops::Bound::Excluded(key), std::ops::Bound::Included(max)))
        {
            // this child is inside the covered range,
            // which means its a descendent of a child that's already been yielded.
            // so, we don't want to collect it here.
            if child.start < covered {
                continue;
            }

            // completely inside the parent range.
            if child.end <= range.end {
                children.push(child);
                covered = child.end;
            }

            // the child overflows the parent range.
            // need to figure out exactly how we handle this.
            // a "straggler".
            if child.start <= range.end && child.end >= range.end {
                break;
            }
        }

        Ok(children)
    }
}

// the complete file span
fn insert_file_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let max_address = pe
        .module
        .sections
        .iter()
        .map(|sec| sec.virtual_range.end)
        .max()
        .unwrap();
    ranges.insert(base_address, max_address, Structure::File)
}

const sizeof_IMAGE_DOS_HEADER: RVA = 0x40;
const sizeof_Signature: RVA = 0x4;
const sizeof_IMAGE_FILE_HEADER: RVA = 0x14;
const sizeof_IMAGE_SECTION_HEADER: RVA = 0x28;

fn offset_IMAGE_NT_HEADERS(pe: &PE) -> RVA {
    pe.pe.header.dos_header.pe_pointer as RVA
}

fn offset_IMAGE_FILE_HEADER(pe: &PE) -> RVA {
    offset_IMAGE_NT_HEADERS(pe) + sizeof_Signature
}

fn has_optional_header(pe: &PE) -> bool {
    pe.pe.header.coff_header.size_of_optional_header > 0
}

fn offset_IMAGE_OPTIONAL_HEADER(pe: &PE) -> RVA {
    offset_IMAGE_FILE_HEADER(pe) + sizeof_IMAGE_FILE_HEADER
}

fn sizeof_IMAGE_OPTIONAL_HEADER(pe: &PE) -> RVA {
    pe.pe.header.coff_header.size_of_optional_header as RVA
}

fn offset_IMAGE_SECTION_HEADER(pe: &PE) -> RVA {
    if has_optional_header(pe) {
        offset_IMAGE_OPTIONAL_HEADER(pe) + sizeof_IMAGE_OPTIONAL_HEADER(pe)
    } else {
        offset_IMAGE_FILE_HEADER(pe) + sizeof_IMAGE_FILE_HEADER
    }
}

fn insert_dos_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    ranges.insert(
        base_address,
        base_address + sizeof_IMAGE_DOS_HEADER,
        Structure::IMAGE_DOS_HEADER,
    )
}

fn insert_signature_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_NT_HEADERS(pe);
    let end = start + sizeof_Signature;
    ranges.insert(start, end, Structure::Signature)
}

fn insert_image_nt_headers_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    insert_signature_range(ranges, pe)?;

    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_NT_HEADERS(pe);
    let end =
        start + sizeof_Signature + sizeof_IMAGE_FILE_HEADER + (pe.pe.header.coff_header.size_of_optional_header as RVA);
    ranges.insert(start, end, Structure::IMAGE_NT_HEADERS)
}

fn insert_image_file_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_FILE_HEADER(pe);
    let end = start + sizeof_IMAGE_FILE_HEADER;
    ranges.insert(start, end, Structure::IMAGE_FILE_HEADER)
}

fn insert_image_optional_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    if has_optional_header(pe) {
        let base_address = pe.module.address_space.base_address;
        let start = base_address + offset_IMAGE_OPTIONAL_HEADER(pe);
        let end = start + sizeof_IMAGE_OPTIONAL_HEADER(pe);
        ranges.insert(start, end, Structure::IMAGE_OPTIONAL_HEADER)?;
    }
    Ok(())
}

fn insert_file_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let header = pe
        .module
        .sections
        .iter()
        .find(|section| section.virtual_range.start == base_address)
        .unwrap();

    ranges.insert(header.virtual_range.start, header.virtual_range.end, Structure::Header)?;
    insert_dos_header_range(ranges, pe)?;
    insert_image_nt_headers_range(ranges, pe)?;
    insert_image_file_header_range(ranges, pe)?;
    insert_image_optional_header_range(ranges, pe)?;

    Ok(())
}

fn insert_section_header_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let mut offset = base_address + offset_IMAGE_SECTION_HEADER(pe);
    for i in 0..pe.pe.header.coff_header.number_of_sections {
        let section = &pe.pe.sections[i as usize];

        let start = offset;
        let end = start + sizeof_IMAGE_SECTION_HEADER;
        let name = section.name().unwrap_or("").to_string();

        ranges.insert(start, end, Structure::IMAGE_SECTION_HEADER(i, name))?;

        offset += sizeof_IMAGE_SECTION_HEADER;
    }
    Ok(())
}

fn insert_section_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    for (i, sec) in pe.module.sections.iter().enumerate() {
        ranges.insert(
            sec.virtual_range.start,
            sec.virtual_range.end,
            Structure::Section(i as u16, sec.name.to_string()),
        )?;
    }
    Ok(())
}

fn insert_data_directory_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    if has_optional_header(pe) {
        let base_address = pe.module.address_space.base_address;
        let opt = pe.pe.header.optional_header.unwrap();

        #[allow(clippy::type_complexity)]
        let mut directories: Vec<(
            Box<dyn Fn() -> Option<goblin::pe::data_directories::DataDirectory>>,
            Structure,
        )> = vec![];

        directories.push((
            Box::new(|| *opt.data_directories.get_export_table()),
            Structure::ExportTable,
        ));
        // the import table is handled by find_import_data_range
        // directories.push((Box::new(|| *opt.data_directories.get_import_table()),
        // Structure::ImportTable));
        directories.push((
            Box::new(|| *opt.data_directories.get_resource_table()),
            Structure::ResourceTable,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_exception_table()),
            Structure::ExceptionTable,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_certificate_table()),
            Structure::CertificateTable,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_base_relocation_table()),
            Structure::BaseRelocationTable,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_debug_table()),
            Structure::DebugData,
        ));
        directories.push((Box::new(|| *opt.data_directories.get_tls_table()), Structure::TlsTable));
        directories.push((
            Box::new(|| *opt.data_directories.get_load_config_table()),
            Structure::LoadConfigTable,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_bound_import_table()),
            Structure::BoundImportTable,
        ));
        // the import table is handled by find_import_data_range
        // directories.push((Box::new(||
        // *opt.data_directories.get_import_address_table()),
        // Structure::ImportAddressTable));
        directories.push((
            Box::new(|| *opt.data_directories.get_delay_import_descriptor()),
            Structure::DelayImportDescriptor,
        ));
        directories.push((
            Box::new(|| *opt.data_directories.get_clr_runtime_header()),
            Structure::ClrRuntimeHeader,
        ));

        for (f, structure) in directories.into_iter() {
            if let Some(dir) = f() {
                let start = base_address + dir.virtual_address as RVA;
                let end = start + dir.size as RVA;
                ranges.insert(start, end, structure)?;
            }
        }
    }
    Ok(())
}

/// in typical binaries compiled by MSVC,
/// the import table and import address table immediately precede the ASCII
/// strings of the DLLs and exported names required by the program.
//
/// here we search for that region of data by collecting the addresses
///  of these elements (IAT, IT, DLL names, function names).
/// if they are all found close to one another, report the elements as a single
/// range.
fn insert_imports_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let mut addrs: Vec<RVA> = vec![];

    if let Some(import_directory) = get_import_directory(pe)? {
        for import_descriptor in read_import_descriptors(pe, import_directory) {
            addrs.push(base_address + import_descriptor.name);

            for thunk in read_thunks(pe, &import_descriptor) {
                if let IMAGE_THUNK_DATA::Function(va) = thunk {
                    addrs.push(base_address + va + 2 as RVA);
                }
            }
        }
    }

    if addrs.len() > 1 {
        addrs.sort();

        // TODO: ensure these all show up near one another.

        let last_addr = addrs[addrs.len() - 1];
        let start = addrs[0];
        let end = last_addr + pe.module.address_space.read_ascii(last_addr)?.len() as RVA;

        ranges.insert(start, end, Structure::ImportTable)?;
    }

    Ok(())
}

/// add a range for each basic block. these won't be rendered, though.
/// add a range for each function, from its start through all contiguous basic
/// blocks. only the function start address will be rendered.
fn insert_function_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let functions = lancelot::analysis::pe::find_function_starts(pe)?;

    for &function in functions.iter() {
        // TODO: handle failure here gracefully.
        let cfg = lancelot::analysis::cfg::build_cfg(&pe.module, function)?;

        let mut end = function;
        for bb in cfg.basic_blocks.values() {
            if bb.addr != end {
                break;
            }
            end += bb.length;
        }

        // TODO get function name

        ranges.insert(function, end, Structure::Function(format!("sub_{:x}", function)))?;
    }
    Ok(())
}

fn insert_string_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let mut section_bufs: Vec<Vec<u8>> = pe
        .module
        .sections
        .iter()
        .map(|section| {
            let start = section.virtual_range.start;
            let size = section.virtual_range.end - section.virtual_range.start;
            pe.module.address_space.read_buf(start, size as usize).unwrap()
        })
        .collect();

    for function in lancelot::analysis::pe::find_function_starts(pe)?.into_iter() {
        // TODO: handle failure here gracefully.
        let cfg = lancelot::analysis::cfg::build_cfg(&pe.module, function)?;

        for bb in cfg.basic_blocks.values() {
            let (i, sec) = pe
                .module
                .sections
                .iter()
                .enumerate()
                .find(|(_, section)| section.virtual_range.contains(&bb.addr))
                .unwrap();

            let buf = &mut section_bufs[i];

            let start = bb.addr - sec.virtual_range.start;
            let end = start + bb.length;

            for i in start..end {
                buf[i as usize] = 0x0;
            }
        }
    }

    for (sec, buf) in pe
        .module
        .sections
        .iter()
        .enumerate()
        .map(|(i, sec)| (sec, &section_bufs[i]))
    {
        for (range, s) in util::find_ascii_strings(buf) {
            let start = sec.virtual_range.start + range.start as RVA;
            let end = sec.virtual_range.start + range.end as RVA;
            ranges.insert(start, end, Structure::String(s))?;
        }

        for (range, s) in util::find_ascii_strings(buf) {
            let start = sec.virtual_range.start + range.start as RVA;
            let end = sec.virtual_range.start + range.end as RVA;
            ranges.insert(start, end, Structure::String(s))?;
        }
    }

    Ok(())
}

fn compute_ranges(pe: &PE) -> Result<Ranges> {
    let mut ranges = Default::default();

    insert_file_range(&mut ranges, pe)?;
    insert_file_header_range(&mut ranges, pe)?;
    insert_section_header_ranges(&mut ranges, pe)?;
    insert_section_ranges(&mut ranges, pe)?;
    insert_data_directory_ranges(&mut ranges, pe)?;
    insert_imports_range(&mut ranges, pe)?;
    insert_function_ranges(&mut ranges, pe)?;
    insert_string_ranges(&mut ranges, pe)?;

    Ok(ranges)
}

fn prefix(depth: usize) {
    for _ in 0..depth {
        print!("  ");
    }
}

fn render_range<'a>(ranges: &'a Ranges, range: &'a Range, depth: usize) -> Result<()> {
    let children = ranges.get_children(range)?;

    if children.is_empty() {
        prefix(depth);
        println!("{:#x}: {:x?}", range.start, range.structure);
    } else {
        prefix(depth);
        println!("[{:#x}: {:x?}]", range.start, range.structure)
    }

    for child in children.into_iter() {
        render_range(ranges, child, depth + 1)?;
    }

    Ok(())
}

fn render(ranges: &Ranges) -> Result<()> {
    let root = ranges.root()?;
    render_range(ranges, root, 0)?;

    println!("ok");
    Ok(())
}

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::clap_app!(lancelot =>
        (author: "Willi Ballenthin <william.ballenthin@mandiant.com>")
        (about: "Somewhere between strings.exe and PEView")
        (@arg verbose: -v --verbose +multiple "log verbose messages")
        (@arg quiet: -q --quiet "disable informational messages")
        (@arg input: +required "path to file to analyze"))
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

    let filename = matches.value_of("input").unwrap();
    debug!("input: {}", filename);

    let buf = util::read_file(filename)?;
    let pe = load_pe(&buf)?;

    let ranges = compute_ranges(&pe)?;
    render(&ranges)?;

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
