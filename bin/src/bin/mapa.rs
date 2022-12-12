// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

// TODO: resource data section
// TODO: overlay
// TODO: stack strings
// TODO: function names
// TODO: flirt function names

use std::collections::BTreeMap;

use ansi_term::Colour as Color;
use anyhow::{anyhow, Result};
use log::{debug, error};

use lancelot::{
    analysis::cfg::{InstructionIndex, CFG},
    aspace::{AbsoluteAddressSpace, AddressSpace},
    loader::pe::{
        imports::{get_import_directory, read_import_descriptors, read_thunks, IMAGE_THUNK_DATA},
        rsrc::{NodeChild, NodeIdentifier, ResourceDataType, ResourceSectionData},
        PE,
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
    Resource(String),
    String(String),
    Function(String),
    Overlay,
}

impl std::fmt::Display for Structure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Structure::File => write!(f, "file"),
            Structure::Header => write!(f, "headers"),
            Structure::IMAGE_DOS_HEADER => write!(f, "IMAGE_DOS_HEADER"),
            Structure::IMAGE_NT_HEADERS => write!(f, "IMAGE_NT_HEADERS"),
            Structure::Signature => write!(f, "signature"),
            Structure::IMAGE_FILE_HEADER => write!(f, "IMAGE_FILE_HEADER"),
            Structure::IMAGE_OPTIONAL_HEADER => write!(f, "IMAGE_OPTIONAL_HEADER"),
            Structure::IMAGE_SECTION_HEADER(_, name) => write!(f, "IMAGE_SECTION_HEADER {}", name),
            Structure::Section(_, name) => write!(f, "section {}", name),
            Structure::ImportTable => write!(f, "import table"),
            Structure::ExportTable => write!(f, "export table"),
            Structure::ResourceTable => write!(f, "resource table"),
            Structure::ExceptionTable => write!(f, "exception table"),
            Structure::CertificateTable => write!(f, "certificate table"),
            Structure::BaseRelocationTable => write!(f, "base relocation table"),
            Structure::DebugData => write!(f, "debug data"),
            Structure::TlsTable => write!(f, "TLS table"),
            Structure::LoadConfigTable => write!(f, "load config table"),
            Structure::BoundImportTable => write!(f, "bound import table"),
            Structure::DelayImportDescriptor => write!(f, "delay import descriptor"),
            Structure::ClrRuntimeHeader => write!(f, "CLR runtime header"),
            Structure::String(s) => write!(f, "string: {}", s),
            Structure::Function(name) => write!(f, "function: {}", name),
            Structure::Resource(name) => write!(f, "resource: {}", name),
            Structure::Overlay => write!(f, "overlay"),
        }
    }
}

type FileOffset = u64;

#[derive(Debug)]
struct Range {
    start:     FileOffset,
    end:       FileOffset,
    structure: Structure,
}

#[derive(Default)]
struct Ranges {
    // key: (start, -end)
    map: BTreeMap<(FileOffset, i64), Range>,
}

impl Ranges {
    fn insert(&mut self, start: FileOffset, end: FileOffset, structure: Structure) -> Result<()> {
        if end > i64::MAX as FileOffset {
            return Err(anyhow!("address too large (>= i64::MAX)"));
        }

        let key = (start, -(end as i64));
        let range = Range { start, end, structure };

        self.map.insert(key, range);

        Ok(())
    }

    fn va_insert(&mut self, pe: &PE, start: VA, end: VA, structure: Structure) -> Result<()> {
        let pstart = pe.module.file_offset(start)? as FileOffset;
        let plen = (end - start) as RVA;
        let pend = pstart + plen as FileOffset;
        self.insert(pstart, pend, structure)
    }

    fn root(&self) -> &Range {
        self.map.values().next().unwrap()
    }

    fn has_children(&self, range: &Range) -> bool {
        let key = (range.start, -(range.end as i64));
        let max = (u64::MAX, i64::MIN);

        if let Some((_, child)) = self
            .map
            .range((std::ops::Bound::Excluded(key), std::ops::Bound::Included(max)))
            .next()
        {
            return child.end <= range.end;
        }
        false
    }

    /// find ranges that fall within the given range.
    /// only collect the ranges that are direct children of the range.
    fn get_children(&self, range: &Range) -> Vec<&Range> {
        let key = (range.start, -(range.end as i64));
        let max = (u64::MAX, i64::MIN);

        // covered is the last address yielded so far.
        // once we yield a direct child, we don't want to yield its children.
        let mut covered = -1i64;

        let mut children = vec![];
        for (_, child) in self
            .map
            .range((std::ops::Bound::Excluded(key), std::ops::Bound::Included(max)))
        {
            // this child is inside the covered range,
            // which means its a descendent of a child that's already been yielded.
            // so, we don't want to collect it here.
            if (child.start as i64) < covered {
                continue;
            }

            // completely inside the parent range.
            if child.end <= range.end {
                children.push(child);
                covered = child.end as i64;
            }

            // the child overflows the parent range.
            // need to figure out exactly how we handle this.
            // a "straggler".
            //
            // ```text
            // ********        range
            //    #########    child
            // ```
            #[allow(clippy::suspicious_operation_groupings)]
            if child.start <= range.end && child.end >= range.end {
                break;
            }
        }

        children
    }
}

/// convert a `Ranges<FileOffset>` to `Ranges<VA>` using a PE
fn fo_to_va_ranges(pe: &PE, src: Ranges) -> Ranges {
    let mut dst: Ranges = Ranges {
        map: Default::default(),
    };

    for ((file_offset, end), v) in src.map.into_iter() {
        if let Ok(va) = pe.module.virtual_address(file_offset) {
            // need to fixup the file structure, to encompass the complete module range,
            // not just file sizes.
            let end = if let Structure::File = v.structure {
                pe.module
                    .sections
                    .iter()
                    .map(|sec| sec.virtual_range.end)
                    .max()
                    .unwrap()
            } else {
                let delta = va - file_offset;
                (-end) as u64 + delta
            };

            let key = (va, -(end as i64));
            let value = Range {
                start: va,
                end,
                structure: v.structure,
            };

            dst.map.insert(key, value);
        } else {
            debug!("file offset not found in loaded module: {:#08x}", file_offset);
        }
    }

    dst
}

fn get_overlay_range(buf: &[u8], pe: &PE) -> (FileOffset, FileOffset) {
    let start = pe
        .module
        .sections
        .iter()
        .map(|sec| sec.physical_range.end)
        .max()
        .unwrap();

    let end = buf.len();

    (start as FileOffset, end as FileOffset)
}

fn insert_overlay_ranges(ranges: &mut Ranges, buf: &[u8], pe: &PE) -> Result<()> {
    let (start, end) = get_overlay_range(buf, pe);
    ranges.insert(start, end, Structure::Overlay)?;

    let buf = &buf[start as usize..end as usize];

    for (range, s) in util::find_ascii_strings(buf) {
        let rstart = start + range.start as FileOffset;
        let rend = start + range.end as FileOffset;
        ranges.insert(rstart, rend, Structure::String(s))?;
    }

    for (range, s) in util::find_unicode_strings(buf) {
        let rstart = start + range.start as FileOffset;
        let rend = start + range.end as FileOffset;
        ranges.insert(rstart, rend, Structure::String(s))?;
    }

    Ok(())
}

// the complete file span
fn insert_file_range(ranges: &mut Ranges, buf: &[u8], pe: &PE) -> Result<()> {
    ranges.insert(0, buf.len() as FileOffset, Structure::File)?;

    insert_overlay_ranges(ranges, buf, pe)?;

    Ok(())
}

const sizeof_IMAGE_DOS_HEADER: RVA = 0x40;
const sizeof_Signature: RVA = 0x4;
const sizeof_IMAGE_FILE_HEADER: RVA = 0x14;
const sizeof_IMAGE_SECTION_HEADER: RVA = 0x28;

fn offset_IMAGE_NT_HEADERS(pe: &PE) -> RVA {
    pe.header.dos_header.pe_pointer as RVA
}

fn offset_IMAGE_FILE_HEADER(pe: &PE) -> RVA {
    offset_IMAGE_NT_HEADERS(pe) + sizeof_Signature
}

fn has_optional_header(pe: &PE) -> bool {
    pe.header.coff_header.size_of_optional_header > 0
}

fn offset_IMAGE_OPTIONAL_HEADER(pe: &PE) -> RVA {
    offset_IMAGE_FILE_HEADER(pe) + sizeof_IMAGE_FILE_HEADER
}

fn sizeof_IMAGE_OPTIONAL_HEADER(pe: &PE) -> RVA {
    pe.header.coff_header.size_of_optional_header as RVA
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
    ranges.va_insert(
        pe,
        base_address,
        base_address + sizeof_IMAGE_DOS_HEADER,
        Structure::IMAGE_DOS_HEADER,
    )
}

fn insert_signature_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_NT_HEADERS(pe);
    let end = start + sizeof_Signature;
    ranges.va_insert(pe, start, end, Structure::Signature)
}

fn insert_image_nt_headers_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    insert_signature_range(ranges, pe)?;

    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_NT_HEADERS(pe);
    let end =
        start + sizeof_Signature + sizeof_IMAGE_FILE_HEADER + (pe.header.coff_header.size_of_optional_header as RVA);
    ranges.va_insert(pe, start, end, Structure::IMAGE_NT_HEADERS)
}

fn insert_image_file_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let start = base_address + offset_IMAGE_FILE_HEADER(pe);
    let end = start + sizeof_IMAGE_FILE_HEADER;
    ranges.va_insert(pe, start, end, Structure::IMAGE_FILE_HEADER)
}

fn insert_image_optional_header_range(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    if has_optional_header(pe) {
        let base_address = pe.module.address_space.base_address;
        let start = base_address + offset_IMAGE_OPTIONAL_HEADER(pe);
        let end = start + sizeof_IMAGE_OPTIONAL_HEADER(pe);
        ranges.va_insert(pe, start, end, Structure::IMAGE_OPTIONAL_HEADER)?;
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

    ranges.va_insert(
        pe,
        header.virtual_range.start,
        header.virtual_range.end,
        Structure::Header,
    )?;
    insert_dos_header_range(ranges, pe)?;
    insert_image_nt_headers_range(ranges, pe)?;
    insert_image_file_header_range(ranges, pe)?;
    insert_image_optional_header_range(ranges, pe)?;

    Ok(())
}

fn insert_section_header_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    let base_address = pe.module.address_space.base_address;
    let mut offset = base_address + offset_IMAGE_SECTION_HEADER(pe);
    let gob = pe.pe()?;
    for i in 0..gob.header.coff_header.number_of_sections {
        let section = &gob.sections[i as usize];

        let start = offset;
        let end = start + sizeof_IMAGE_SECTION_HEADER;
        let name = section.name().unwrap_or("").to_string();

        ranges.va_insert(pe, start, end, Structure::IMAGE_SECTION_HEADER(i, name))?;

        offset += sizeof_IMAGE_SECTION_HEADER;
    }
    Ok(())
}

fn insert_section_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    for (i, sec) in pe.module.sections.iter().enumerate() {
        ranges.insert(
            sec.physical_range.start as FileOffset,
            sec.physical_range.end as FileOffset,
            Structure::Section(i as u16, sec.name.to_string()),
        )?;
    }
    Ok(())
}

fn insert_data_directory_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    if has_optional_header(pe) {
        let base_address = pe.module.address_space.base_address;
        let opt = pe.header.optional_header.unwrap();

        #[allow(clippy::type_complexity)]
        let directories: Vec<(
            Box<dyn Fn() -> Option<goblin::pe::data_directories::DataDirectory>>,
            Structure,
        )> = vec![
            (
                Box::new(|| *opt.data_directories.get_export_table()),
                Structure::ExportTable,
            ),
            // the import table is handled by find_import_data_range
            // directories.push((Box::new(|| *opt.data_directories.get_import_table()),
            // Structure::ImportTable));
            (
                Box::new(|| *opt.data_directories.get_resource_table()),
                Structure::ResourceTable,
            ),
            (
                Box::new(|| *opt.data_directories.get_exception_table()),
                Structure::ExceptionTable,
            ),
            (
                Box::new(|| *opt.data_directories.get_certificate_table()),
                Structure::CertificateTable,
            ),
            (
                Box::new(|| *opt.data_directories.get_base_relocation_table()),
                Structure::BaseRelocationTable,
            ),
            (
                Box::new(|| *opt.data_directories.get_debug_table()),
                Structure::DebugData,
            ),
            (Box::new(|| *opt.data_directories.get_tls_table()), Structure::TlsTable),
            (
                Box::new(|| *opt.data_directories.get_load_config_table()),
                Structure::LoadConfigTable,
            ),
            (
                Box::new(|| *opt.data_directories.get_bound_import_table()),
                Structure::BoundImportTable,
            ),
            // the import table is handled by find_import_data_range
            // directories.push((Box::new(||
            // *opt.data_directories.get_import_address_table()),
            // Structure::ImportAddressTable));
            (
                Box::new(|| *opt.data_directories.get_delay_import_descriptor()),
                Structure::DelayImportDescriptor,
            ),
            (
                Box::new(|| *opt.data_directories.get_clr_runtime_header()),
                Structure::ClrRuntimeHeader,
            ),
        ];

        for (f, structure) in directories.into_iter() {
            if let Some(dir) = f() {
                let start = base_address + dir.virtual_address as RVA;
                let end = start + dir.size as RVA;
                ranges.va_insert(pe, start, end, structure)?;
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
                    addrs.push(base_address + va + 2u64);
                }
            }
        }
    }

    if addrs.len() > 1 {
        addrs.sort_unstable();

        // TODO: ensure these all show up near one another.

        let last_addr = addrs[addrs.len() - 1];
        let start = addrs[0];
        let end = last_addr + pe.module.address_space.read_ascii(last_addr, 4)?.len() as RVA;

        ranges.va_insert(pe, start, end, Structure::ImportTable)?;
    }

    Ok(())
}

fn insert_resource_ranges_inner(
    ranges: &mut Ranges,
    _pe: &PE,
    rsrc: &ResourceSectionData,
    prefix: String,
    node: NodeChild,
) -> Result<()> {
    match node {
        NodeChild::Data(d) => {
            // rsrc RVAs are file offsets?
            ranges.insert(
                d.rva as FileOffset,
                (d.rva + d.size) as FileOffset,
                Structure::Resource(prefix),
            )?;
        }
        NodeChild::Node(child) => {
            for (entry, child) in child.children(rsrc)?.into_iter() {
                // when the first element is recognized, render it like `RT_VERSION`,
                // otherwise, like `0x0`.
                let prefix = match entry.id(rsrc)? {
                    NodeIdentifier::ID(id) => {
                        if prefix.is_empty() {
                            match ResourceDataType::from_u32(id) {
                                Some(dt) => format!("{:?}", dt),
                                None => format!("{:#x}", id),
                            }
                        } else {
                            format!("{}/{:#x}", prefix, id)
                        }
                    }
                    NodeIdentifier::Name(s) => {
                        if prefix.is_empty() {
                            s.clone()
                        } else {
                            format!("{}/{}", prefix, s)
                        }
                    }
                };

                insert_resource_ranges_inner(ranges, _pe, rsrc, prefix, child)?;
            }
        }
    }

    Ok(())
}

fn insert_resource_ranges(ranges: &mut Ranges, pe: &PE) -> Result<()> {
    if let Some(rsrc) = ResourceSectionData::from_pe(pe)? {
        let root = rsrc.root()?;
        insert_resource_ranges_inner(ranges, pe, &rsrc, "".to_string(), NodeChild::Node(root))?;
    }

    Ok(())
}

/// add a range for each basic block. these won't be rendered, though.
/// add a range for each function, from its start through all contiguous basic
/// blocks. only the function start address will be rendered.
fn insert_function_ranges(ranges: &mut Ranges, pe: &PE, cfg: &CFG, functions: &[VA]) -> Result<()> {
    for &function in functions.iter() {
        let mut blocks = cfg.get_reachable_blocks(function).collect::<Vec<_>>();
        blocks.sort_unstable_by_key(|&bb| bb.address);

        let mut end = function;
        for bb in blocks.iter() {
            if bb.address != end {
                break;
            }
            end += bb.length;
        }
        ranges.va_insert(pe, function, end, Structure::Function(format!("sub_{:x}", function)))?;
    }

    Ok(())
}

fn insert_string_ranges(ranges: &mut Ranges, pe: &PE, cfg: &CFG, functions: &[VA]) -> Result<()> {
    // create a copy of the module.
    // for each basic block, zero out its region.
    // then look for strings in the remaining data.

    let mut section_bufs: Vec<Vec<u8>> = pe
        .module
        .sections
        .iter()
        .map(|section| {
            let start = section.virtual_range.start;
            let size = section.virtual_range.end - section.virtual_range.start;
            pe.module.address_space.read_bytes(start, size as usize).unwrap()
        })
        .collect();

    for &function in functions.iter() {
        for bb in cfg.get_reachable_blocks(function) {
            let (i, sec) = pe
                .module
                .sections
                .iter()
                .enumerate()
                .find(|(_, section)| section.virtual_range.contains(&bb.address))
                .unwrap();

            let buf = &mut section_bufs[i];

            let start = bb.address - sec.virtual_range.start;
            let mut end = start + bb.length;
            if end > sec.physical_range.end {
                end = sec.physical_range.end;
            }

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
            ranges.va_insert(pe, start, end, Structure::String(s))?;
        }

        for (range, s) in util::find_unicode_strings(buf) {
            let start = sec.virtual_range.start + range.start as RVA;
            let end = sec.virtual_range.start + range.end as RVA;
            ranges.va_insert(pe, start, end, Structure::String(s))?;
        }
    }

    Ok(())
}

fn compute_ranges(buf: &[u8], pe: &PE) -> Result<Ranges> {
    let mut ranges = Default::default();

    insert_file_range(&mut ranges, buf, pe)?;
    insert_overlay_ranges(&mut ranges, buf, pe)?;
    insert_file_header_range(&mut ranges, pe)?;
    insert_section_header_ranges(&mut ranges, pe)?;
    insert_section_ranges(&mut ranges, pe)?;
    insert_data_directory_ranges(&mut ranges, pe)?;
    insert_imports_range(&mut ranges, pe)?;
    insert_resource_ranges(&mut ranges, pe)?;

    let mut insns: InstructionIndex = Default::default();
    let functions = lancelot::analysis::pe::find_function_starts(pe)?;
    for function in functions.iter() {
        insns.build_index(&pe.module, *function)?;
    }
    let cfg = CFG::from_instructions(&pe.module, insns)?;

    insert_function_ranges(&mut ranges, pe, &cfg, &functions)?;
    insert_string_ranges(&mut ranges, pe, &cfg, &functions)?;

    Ok(ranges)
}

/// width of a "block".
/// try to match the width of a hex dump nicely.
const WIDTH: usize = 88;
const MUTED: Color = Color::Fixed(8);

/// prefix the given (potentially multi-line) string
/// with the repeated prefix (here: `|  `).
fn prefix(depth: usize, s: &str) -> String {
    let mut ret: Vec<String> = Default::default();
    for line in s.split('\n') {
        #[allow(clippy::same_item_push)]
        for _ in 0..depth {
            ret.push(MUTED.paint("│  ").to_string());
        }
        ret.push(String::from(line));
        ret.push(String::from("\n"));
    }
    String::from(ret.join("").trim_end())
}

/// print the given (potentially multi-line) string
/// with the repeated prefix (here: `|  `).
fn prefixln(depth: usize, s: &str) {
    println!("{}", prefix(depth, s));
}

/// render the range block start separator like:
///
///   ┌── 0x000290 IMAGE_SECTION_HEADER .rsrc ────
///
/// pads the line with `WIDTH` characters,
fn format_block_start(range: &Range) -> String {
    let label = format!(" {:#08x} {} ", range.start, range.structure);
    let prefix = "┌──";

    let mut chars: Vec<char> = Vec::with_capacity(WIDTH);
    chars.extend(MUTED.paint(prefix).to_string().chars());
    chars.extend(label.chars());

    let dash = MUTED.paint("─").to_string();
    for _ in 0..WIDTH - (label.len() + prefix.len()) {
        chars.extend(dash.chars());
    }

    chars.iter().collect()
}

/// render the range block end separator like:
///
///     └── 0x000290  ────────────────────────────
fn format_block_end(range: &Range) -> String {
    let label = format!(" {:#08x} ", range.end);
    let prefix = "└──";

    let mut chars: Vec<char> = Vec::with_capacity(WIDTH);
    chars.extend(MUTED.paint(prefix).to_string().chars());
    chars.extend(label.chars());

    let dash = MUTED.paint("─").to_string();
    for _ in 0..WIDTH - (label.len() + prefix.len()) {
        chars.extend(dash.chars());
    }

    chars.iter().collect()
}

fn format_range_hex(address_space: &AbsoluteAddressSpace, range: &Range) -> String {
    let mut ostream: Vec<u8> = Default::default();
    let buf = address_space
        .read_bytes(range.start, (range.end - range.start) as usize)
        .unwrap();
    let b = &buf[..];
    let mut h = hexyl::PrinterBuilder::new(&mut ostream)
        .show_color(true)
        .show_char_panel(true)
        .show_position_panel(true)
        .with_border_style(hexyl::BorderStyle::None)
        .enable_squeezing(true)
        .num_panels(1)
        .build();
    h.display_offset(range.start);
    h.print_all(b).unwrap();
    let hex = String::from_utf8(ostream).unwrap();
    //let hex = lancelot::util::hexdump(&buf[range.start as usize..range.end as
    // usize], range.start);
    format!(
        "{}\n{}\n{}",
        format_block_start(range),
        prefix(1, hex.trim_end()),
        format_block_end(range)
    )
}

fn will_render_as_block<'a>(ranges: &'a Ranges, range: &'a Range) -> bool {
    match &range.structure {
        // these are always rendered inline
        Structure::Function(_) => false,
        Structure::String(_) => false,
        // these are always rendered as a hex dump
        Structure::IMAGE_DOS_HEADER => true,
        Structure::Signature => true,
        Structure::IMAGE_FILE_HEADER => true,
        Structure::IMAGE_OPTIONAL_HEADER => true,
        Structure::IMAGE_SECTION_HEADER(_, _) => true,
        // anything else is rendered inline if it has no children.
        // otherwise, as a block.
        _ => ranges.has_children(range),
    }
}

/// write the given range to output
fn render_range<'a>(
    address_space: &AbsoluteAddressSpace,
    ranges: &'a Ranges,
    range: &'a Range,
    depth: usize,
) -> Result<()> {
    match &range.structure {
        Structure::Function(s) => prefixln(depth, &format!(" {:#08x}: {}", range.start, s)),
        Structure::String(s) => prefixln(depth, &format!(" {:#08x}: \"{}\"", range.start, s)),
        Structure::IMAGE_DOS_HEADER => prefixln(depth, &format_range_hex(address_space, range)),
        Structure::Signature => prefixln(depth, &format_range_hex(address_space, range)),
        Structure::IMAGE_FILE_HEADER => prefixln(depth, &format_range_hex(address_space, range)),
        Structure::IMAGE_OPTIONAL_HEADER => prefixln(depth, &format_range_hex(address_space, range)),
        Structure::IMAGE_SECTION_HEADER(_, _) => prefixln(depth, &format_range_hex(address_space, range)),
        _ => {
            let children = ranges.get_children(range);
            let has_children = !children.is_empty();

            if !has_children {
                prefixln(depth, &format!(" {:#08x}: [{}]", range.start, range.structure))
            } else {
                prefixln(depth, &format_block_start(range));

                // iterate over pairs of children.
                // always render the first.
                // then check and see if they're inline entryes (e.g. both strings).
                // if not, then render a line between them.
                // after this loop, we'll render the very final child.
                for siblings in children.windows(2) {
                    let c1 = siblings[0];
                    let c2 = siblings[1];

                    render_range(address_space, ranges, c1, depth + 1)?;

                    if !(!will_render_as_block(ranges, c1) && !will_render_as_block(ranges, c2)) {
                        prefixln(depth + 1, "");
                    }
                }

                let last_child = children[children.len() - 1];
                render_range(address_space, ranges, last_child, depth + 1)?;

                prefixln(depth, &format_block_end(range));
            }
        }
    }

    Ok(())
}

/// write the output
fn render(address_space: &AbsoluteAddressSpace, ranges: &Ranges) -> Result<()> {
    let root = ranges.root();
    render_range(address_space, ranges, root, 0)?;
    Ok(())
}

fn _main() -> Result<()> {
    better_panic::install();

    let matches = clap::App::new("mapa")
        .author("Willi Ballenthin <william.ballenthin@mandiant.com>")
        .about("Somewhere between strings.exe and PEView")
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
            clap::Arg::new("va")
                .long("va")
                .action(clap::ArgAction::SetTrue)
                .help("output addresses as mapped into memory"),
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

    let filename = matches.value_of("input").unwrap();
    debug!("input: {}", filename);

    let buf = util::read_file(filename)?;
    let pe = PE::from_bytes(&buf)?;

    // returns a Ranges containing FileOffsets
    let ranges = compute_ranges(&buf, &pe)?;

    if matches.get_flag("va") {
        // user wants to display output as VAs
        // so convert the Ranges<FileOffset> to Ranges<VA>
        // and use the loaded PE as the source data.
        let ranges = fo_to_va_ranges(&pe, ranges);
        render(&pe.module.address_space, &ranges)?;
    } else {
        // user wants to display the output as file offsets.
        // ranges is already a Ranges<FileOffset>,
        // so construct an aspace with the file content at 0x0.
        let address_space = lancelot::aspace::AbsoluteAddressSpace {
            base_address: 0x0,
            relative:     lancelot::aspace::RelativeAddressSpace::from_buf(&buf),
        };
        render(&address_space, &ranges)?;
    };

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
