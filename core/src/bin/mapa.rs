// TODO:
//   - list functions
//   - colors
//   - section entropy
//   - resource parsing

// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate log;
extern crate lancelot;
extern crate chrono;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate clap;

use std::collections::HashMap;
use fern;
use std::ops::Range;

use better_panic;
use failure::{Error, Fail};
use goblin::Object;
use log::{error, warn, info, debug};
use regex::bytes::Regex;

use lancelot::arch::{RVA};
use lancelot::workspace::Workspace;
use lancelot::analysis::pe::imports;


#[derive(Debug, Fail)]
pub enum MainError {
    #[fail(display = "foo")]
    Foo,
    #[fail(display = "Invalid PE file")]
    InvalidFile,
    #[fail(display = "Unmapped address")]
    UnmappedVA,
}

/*
    File
      Header,
        IMAGE_DOS_HEADER,
        IMAGE_NT_HEADERS,
          Signature
          IMAGE_FILE_HEADER,
          IMAGE_OPTIONAL_HEADER,
      IMAGE_SECTION_HEADER,
      Section(u32),
*/

#[derive(Debug, Clone)]
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
            Structure::ExportTable=> write!(f, "export table"),
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
        }
    }
}

fn cmp_ranges<T: PartialOrd>(a: &Range<T>, b: &Range<T>) -> std::cmp::Ordering {
    if a.start < b.start {
        std::cmp::Ordering::Less
    } else if a.start > b.start {
        std::cmp::Ordering::Greater
    } else if a.end < b.end {
        std::cmp::Ordering::Greater
    } else if a.end > b.end {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Equal
    }
}

fn find_ascii_strings(buf: &[u8]) -> Vec<(Range<usize>, String)> {
    lazy_static! {
        static ref ASCII_RE: Regex = Regex::new("[ -~]{4,}").unwrap();
    }

    ASCII_RE.captures_iter(buf)
        .map(|cap| {
            // guaranteed to have at least one hit
            let mat = cap.get(0).unwrap();

            // this had better be ASCII, and therefore able to be decoded.
            let s = String::from_utf8(mat.as_bytes().to_vec()).unwrap();

            (Range {
                start: mat.start(),
                end: mat.end(),
            }, s)
        })
        .collect()
}

fn find_unicode_strings(buf: &[u8]) -> Vec<(Range<usize>, String)> {
    lazy_static! {
        static ref UNICODE_RE: Regex = Regex::new("([ -~]\x00){4,}").unwrap();
    }

    UNICODE_RE.captures_iter(buf)
        .map(|cap| {
            // guaranteed to have at least one hit
            let mat = cap.get(0).unwrap();

            // this had better be ASCII, and therefore able to be decoded.
            let bytes = mat.as_bytes();
            let words: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|w| u16::from(w[1]) << 8 | u16::from(w[0]))
                .collect();

            // danger: the unwrap here might feasibly fail
            let s = String::from_utf16(&words).unwrap();

            (Range {
                start: mat.start(),
                end: mat.end(),
            }, s)
        })
        .collect()
}

fn find_strings(buf: &[u8]) -> Vec<(Range<usize>, String)> {
    let mut strings: Vec<(Range<usize>, String)> = vec![];
    let mut ascii = find_ascii_strings(buf);
    let mut unicode = find_unicode_strings(buf);

    strings.append(&mut ascii);
    strings.append(&mut unicode);

    strings.sort_by(|a, b| cmp_ranges(&a.0, &b.0));

    strings
}

struct MapNode {
    range: Range<u64>,
    structure: Structure,
    children: Vec<MapNode>,
}

impl MapNode {
    fn new(range: Range<u64>, structure: Structure) -> MapNode {
        MapNode {
            range,
            structure,
            children: vec![],
        }
    }

    fn contains(&self, other: &MapNode) -> bool {
        self.range.start <= other.range.start
          && self.range.end >= other.range.end
    }

    fn insert(&mut self, other: MapNode) {
        if ! self.contains(&other) {
            panic!("this node does not contain the child")
        }

        match self.children.iter_mut().find(|child| child.contains(&other)) {
            Some(child) => child.insert(other),
            None => {
                self.children.push(other);
                self.children.sort_by(|a, b| cmp_ranges(&a.range, &b.range));
            }
        }
    }

    fn render_structure_hex(&self, buf: &[u8]) -> Result<Vec<String>, Error> {
        let mut ret: Vec<String> = vec![];
        // ref: https://www.fileformat.info/info/unicode/block/box_drawing/list.htm
        ret.push(format!(""));
        ret.push(format!("┌── {:#08x} {} ────────", self.range.start, self.structure));
        let region = &buf[self.range.start as usize..self.range.end as usize];
        for line in lancelot::util::hexdump(region,
                                            self.range.start as usize).split("\n") {
            if line != "" {
                ret.push(format!("│   {}", line))
            }
        }
        ret.push(format!("└── {:#08x} ────────────────────────", self.range.end));
        ret.push(format!(""));
        Ok(ret)
    }

    fn render_structure_tree(&self, buf: &[u8]) -> Result<Vec<String>, Error> {
        let mut ret: Vec<String> = vec![];
        // ref: https://www.fileformat.info/info/unicode/block/box_drawing/list.htm
        ret.push(format!(""));
        ret.push(format!("┌── {:#08x} {} ────────", self.range.start, self.structure));
        for child in self.children.iter() {
            for line in child.render(buf)?.iter() {
                ret.push(format!("│  {}", line))
            }
        }
        ret.push(format!("└── {:#08x} ────────────────────────", self.range.end));
        ret.push(format!(""));
        Ok(ret)
    }

    fn render(&self, buf: &[u8]) -> Result<Vec<String>, Error> {
        let ret = match (self.children.len(), &self.structure) {
            (_, Structure::String(s)) => vec![format!("    {:#08x} string \"{}\"", self.range.start, s)],
            (_, Structure::IMAGE_SECTION_HEADER(_, _)) => self.render_structure_hex(buf)?,
            (_, Structure::IMAGE_DOS_HEADER) => self.render_structure_hex(buf)?,
            (_, Structure::Signature) => self.render_structure_hex(buf)?,
            (_, Structure::IMAGE_FILE_HEADER) => self.render_structure_hex(buf)?,
            (_, Structure::IMAGE_OPTIONAL_HEADER) => self.render_structure_hex(buf)?,
            (0, _) => vec![format!("    {:#08x} [ {} ]", self.range.start, self.structure)],
            (_, _) => self.render_structure_tree(buf)?,
        };
        Ok(ret)
    }
}

fn get_node(map: &Map, range: Range<u64>) -> MapNode {
    MapNode::new(range.clone(), map.locations[&range].clone())
}

fn build_tree(map: &Map) -> Result<MapNode, Error> {
    let mut locations: Vec<Range<u64>> = map.locations.keys().cloned().collect();
    locations.sort_by(|a, b| cmp_ranges(a, b));
    locations.reverse();
    let mut root_node = get_node(map, locations.pop().unwrap());  // warning

    while !locations.is_empty() {
        root_node.insert(get_node(map, locations.pop().unwrap()));
    }

    Ok(root_node)
}

struct Map {
    locations: HashMap<Range<u64>, Structure>,
}

fn compute_map(ws: &Workspace) -> Result<Map, Error> {
    let pe = match Object::parse(&ws.buf) {
        Ok(Object::PE(pe)) => pe,
        _ => return Err(MainError::InvalidFile.into()),
    };

    let mut locations: HashMap<Range<u64>, Structure> = HashMap::new();

    locations.insert(
        Range {
            start: 0,
            end: ws.buf.len() as u64,
        },
        Structure::File,
    );

    let sizeof_IMAGE_DOS_HEADER = 0x40;
    locations.insert(
        Range {
            start: 0,
            end: sizeof_IMAGE_DOS_HEADER,
        },
        Structure::IMAGE_DOS_HEADER,
    );

    let offset_IMAGE_NT_HEADERS = pe.header.dos_header.pe_pointer as u64;
    let sizeof_Signature: u64 = 0x4;
    let sizeof_IMAGE_FILE_HEADER: u64 = 0x14;
    locations.insert(
        Range {
            start: offset_IMAGE_NT_HEADERS,
            end: offset_IMAGE_NT_HEADERS
                + sizeof_Signature
                + sizeof_IMAGE_FILE_HEADER
                + (pe.header.coff_header.size_of_optional_header as u64),
        },
        Structure::IMAGE_NT_HEADERS,
    );

    locations.insert(
        Range {
            start: offset_IMAGE_NT_HEADERS,
            end: offset_IMAGE_NT_HEADERS + sizeof_Signature,
        },
        Structure::Signature,
    );

    let offset_IMAGE_FILE_HEADER = offset_IMAGE_NT_HEADERS + sizeof_Signature;
    locations.insert(
        Range {
            start: offset_IMAGE_FILE_HEADER,
            end: offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER,
        },
        Structure::IMAGE_FILE_HEADER,
    );

    let end_of_headers = if pe.header.coff_header.size_of_optional_header > 0 {
        let offset_IMAGE_OPTIONAL_HEADER = offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER;
        let end_of_headers = offset_IMAGE_OPTIONAL_HEADER
                    + (pe.header.coff_header.size_of_optional_header as u64);
        locations.insert(
            Range {
                start: offset_IMAGE_OPTIONAL_HEADER,
                end: end_of_headers,
            },
            Structure::IMAGE_OPTIONAL_HEADER,
        );
        locations.insert(
            Range {
                start: 0x0,
                end: offset_IMAGE_OPTIONAL_HEADER
                    + (pe.header.coff_header.size_of_optional_header as u64),
            },
            Structure::Header,
        );
        end_of_headers
    } else {
        let end_of_headers = offset_IMAGE_FILE_HEADER + sizeof_IMAGE_FILE_HEADER;
        locations.insert(
            Range {
                start: 0x0,
                end: end_of_headers,
            },
            Structure::Header,
        );
        end_of_headers
    };

    let mut offset_IMAGE_SECTION_HEADER = end_of_headers;
    let sizeof_IMAGE_SECTION_HEADER = 0x28;
    for i in 0..pe.header.coff_header.number_of_sections {
        let section = &pe.sections[i as usize];
        locations.insert(
            Range {
                start: section.pointer_to_raw_data as u64,
                end: (section.pointer_to_raw_data + section.size_of_raw_data) as u64,
            },
            Structure::Section(i, section.name().unwrap_or("").to_string()),
        );

        locations.insert(
            Range {
                start: offset_IMAGE_SECTION_HEADER,
                end: offset_IMAGE_SECTION_HEADER + sizeof_IMAGE_SECTION_HEADER,
            },
            Structure::IMAGE_SECTION_HEADER(i, section.name().unwrap_or("").to_string()),
        );

        offset_IMAGE_SECTION_HEADER += sizeof_IMAGE_SECTION_HEADER;
    }

    if let Some(opt) = pe.header.optional_header {
        let mut directories: Vec<(Box<dyn Fn() -> Option<goblin::pe::data_directories::DataDirectory>>, Structure)> = vec![];
        directories.push((Box::new(|| *opt.data_directories.get_export_table()), Structure::ExportTable));
        // the import table is handled by find_import_data_range
        // directories.push((Box::new(|| *opt.data_directories.get_import_table()), Structure::ImportTable));
        directories.push((Box::new(|| *opt.data_directories.get_resource_table()), Structure::ResourceTable));
        directories.push((Box::new(|| *opt.data_directories.get_exception_table()), Structure::ExceptionTable));
        directories.push((Box::new(|| *opt.data_directories.get_certificate_table()), Structure::CertificateTable));
        directories.push((Box::new(|| *opt.data_directories.get_base_relocation_table()), Structure::BaseRelocationTable));
        directories.push((Box::new(|| *opt.data_directories.get_debug_table()), Structure::DebugData));
        directories.push((Box::new(|| *opt.data_directories.get_tls_table()), Structure::TlsTable));
        directories.push((Box::new(|| *opt.data_directories.get_load_config_table()), Structure::LoadConfigTable));
        directories.push((Box::new(|| *opt.data_directories.get_bound_import_table()), Structure::BoundImportTable));
        // the import table is handled by find_import_data_range
        // directories.push((Box::new(|| *opt.data_directories.get_import_address_table()), Structure::ImportAddressTable));
        directories.push((Box::new(|| *opt.data_directories.get_delay_import_descriptor()), Structure::DelayImportDescriptor));
        directories.push((Box::new(|| *opt.data_directories.get_clr_runtime_header()), Structure::ClrRuntimeHeader));

        for (f, structure) in directories.iter() {
            if let Some(dir) = f() {
                if let Ok(pfile) = rva2pfile(&pe, dir.virtual_address as u64) {
                    locations.insert(
                        Range {
                            start: pfile as u64,
                            end: (pfile + dir.size as usize) as u64,
                        },
                        structure.clone(),
                    );
                }
            }
        }
    }

    // enumerate all the functions,
    // for each function,
    // enumerate all the basic blocks,
    // these regions should be raw instructions (not data).
    //
    // when we find a string, ensure it is not found in a basic block.
    let code_filter = FunctionMap::new(ws);
    for (loc, string) in find_strings(&ws.buf).iter() {
        if let Ok(string_rva) = pfile2rva(&pe, loc.start) {
            if code_filter.find(string_rva).is_none() {
                // no overlap with recognized code.
                // probably a real string.
                locations.insert(Range {
                    start: loc.start as u64,
                    end: loc.end as u64,
                }, Structure::String(string.clone()));
            }
        }
    }

    if let Some(r) = find_import_data_range(&ws)? {
        locations.insert(r, Structure::ImportTable);
    }

    Ok(Map {
        locations
    })
}

/// basic block descriptor.
struct FunctionEntry {
    start: RVA,
    end: RVA,
    func: RVA,
}

struct FunctionMap {
    basic_blocks: Vec<FunctionEntry>,
}

/// layout of basic blocks across the entire file.
impl FunctionMap {
    pub fn new(ws: &Workspace) -> FunctionMap {
        let mut functions = ws.get_functions().collect::<Vec<_>>();
        functions.sort();
        debug!("found {} functions", functions.len());

        let mut basic_blocks = vec![];
        for rva in functions.iter() {
            if let Ok(bbs) = ws.get_basic_blocks(**rva) {
                for bb in bbs.iter() {
                    basic_blocks.push(FunctionEntry {
                        start: bb.addr,
                        end: bb.addr + (bb.length as u32),
                        func: **rva,
                    });
                }
            }
        }
        basic_blocks.sort_unstable_by(|a, b| a.start.cmp(&b.start));
        debug!("found {} basic blocks", basic_blocks.len());

        FunctionMap {
            basic_blocks
        }
    }

    /// is the given address found within a basic block?
    pub fn find(&self, rva: RVA) -> Option<RVA> {
        self.basic_blocks.binary_search_by(|probe| {
            if probe.start > rva{
                std::cmp::Ordering::Greater
            } else if probe.end < rva {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).and_then(|index| Ok(self.basic_blocks[index].func)).ok()
    }
}


// in typical binaries compiled by MSVC,
// the import table and import address table immediately precede the ASCII strings
// of the DLLs and exported names required by the program.
//
// here we search for that region of data by collecting the addresses
//  of these elements (IAT, IT, DLL names, function names).
// if they are all found close to one another, report the elements as a single range.
fn find_import_data_range(ws: &lancelot::Workspace) -> Result<Option<Range<u64>>, Error> {
    let mut addrs: Vec<RVA> = vec![];

    let pe = match Object::parse(&ws.buf) {
        Ok(Object::PE(pe)) => pe,
        _ => panic!("can't analyze unexpected format"),
    };

    let import_directory = {
        let opt_header = match pe.header.optional_header {
            Some(opt_header) => opt_header,
            _ => return Ok(None),
        };

        let import_directory = match opt_header.data_directories.get_import_table() {
            Some(import_directory) => import_directory,
            _ => return Ok(None),
        };

        if let Some(iat) = opt_header.data_directories.get_import_address_table() {
            addrs.push(RVA::from(iat.virtual_address as i64));
        }

        if let Some(iat) = opt_header.data_directories.get_import_table() {
            addrs.push(RVA::from(iat.virtual_address as i64));
        }

        RVA::from(import_directory.virtual_address as i64)
    };

    let psize: usize = ws.loader.get_arch().get_pointer_size() as usize;
    for i in 0..std::usize::MAX {
        // for each DLL entry in the import table...
        let import_descriptor_rva = import_directory + RVA::from(i * 0x14);
        let import_descriptor = imports::read_image_import_descriptor(ws, import_descriptor_rva)?;
        // until the empty entry (last one)
        if import_descriptor.is_empty() {
            break;
        }

        // collect where the dll name is found
        let dll_name_addr = import_descriptor.name;
        addrs.push(dll_name_addr);

        for j in 0..std::usize::MAX {
            // for each function name entry...

            // the Original First Thunk (OFT) remains constant, and points to the IMAGE_IMPORT_BY_NAME.
            // FT and OFT are parallel arrays.
            let original_first_thunk = import_descriptor.original_first_thunk + RVA::from(j * psize);

            // the First Thunk (FT) is the pointer that will be overwritten upon load.
            // entries here may not point to the IMAGE_IMPORT_BY_NAME.
            let first_thunk = import_descriptor.first_thunk + RVA::from(j * psize);

            match imports::read_best_thunk_data(ws, original_first_thunk, first_thunk) {
                Ok(imports::ImageThunkData::Function(rva)) => {
                    // until the empty entry (last one)
                    if rva == RVA(0x0) {
                        break;
                    } else {
                        // collect where the function name is found.
                        let import_name_addr: RVA = rva + RVA::from(2);

                        // sanity check: these strings should be close together.
                        // assume each is within 100 bytes of the prior string.
                        // this won't work if we have really long import names.
                        //
                        // TMPProvider038.dll spreads the import names across an entire section,
                        // which we want to detect and avoid.
                        if import_name_addr > addrs[addrs.len() - 1] + 100 {
                            warn!("detected disjoint import table data");

                            // TODO: maybe this is an error.
                            return Ok(None);
                        }

                        addrs.push(import_name_addr);
                    }
                },
                Ok(imports::ImageThunkData::Ordinal(_)) => { /* pass */ },
                Err(_) => { break },
            };
        }
    }

    if addrs.len() == 0 {
        return Ok(None);
    }

    addrs.sort();
    let last_str_addr = addrs[addrs.len() - 1];
    // if, for some reason, the IAT is the last element, this won't work well.
    let last_str = ws.read_utf8(last_str_addr)?;

    let start_rva = addrs[0];
    let end_rva = last_str_addr + last_str.len();

    Ok(Some(Range {
        start: rva2pfile(&pe, start_rva.into())? as u64,
        end: rva2pfile(&pe,  end_rva.into())? as u64,
    }))
}

pub fn rva2pfile(pe: &goblin::pe::PE, rva: u64) -> Result<usize, Error> {
    // track the minimum section.pointer_to_raw_data.
    // assume all data before this is part of the headers,
    //  and can be indexed directly via the RVA.
    let mut min_section_addr = std::u32::MAX;
    let rva = rva as u32;

    for section in pe.sections.iter() {
        if section.virtual_address <= rva && rva < section.virtual_address + section.virtual_size {
            let offset = rva - section.virtual_address;
            return Ok((section.pointer_to_raw_data + offset) as usize)
        }

        if section.pointer_to_raw_data < min_section_addr {
            min_section_addr = section.pointer_to_raw_data;
        }
    }

    if rva < min_section_addr {
        // this must be found in the headers of the file.
        // and therefore the rva == pfile.
        return Ok(rva as usize);
    }

    return Err(MainError::UnmappedVA.into())
}

pub fn pfile2rva(pe: &goblin::pe::PE, rva: usize) -> Result<RVA, Error> {
    // track the minimum section.pointer_to_raw_data.
    // assume all data before this is part of the headers,
    //  and can be indexed directly via the RVA.
    let mut min_section_addr = std::u32::MAX;
    let rva = rva as u32;

    for section in pe.sections.iter() {
        if section.pointer_to_raw_data <= rva && rva < section.pointer_to_raw_data + section.size_of_raw_data {
            let offset = rva - section.pointer_to_raw_data;
            return Ok(RVA::from(section.virtual_address + offset))
        }

        if section.pointer_to_raw_data < min_section_addr {
            min_section_addr = section.pointer_to_raw_data;
        }
    }

    if rva < min_section_addr {
        // this must be found in the headers of the file.
        // and therefore the rva == pfile.
        return Ok(RVA::from(rva));
    }

    return Err(MainError::UnmappedVA.into())
}

fn render_map(map: &Map, buf: &[u8]) -> Result<(), Error> {
    let tree = build_tree(&map)?;
    for line in tree.render(buf)?.iter() {
        println!("{}", line);
    }

    Ok(())
}

pub fn run(path: &str) -> Result<(), Error> {
    info!("filename: {:?}", path);

    let ws = Workspace::from_file(path)?.load()?;
    let map = compute_map(&ws)?;
    render_map(&map, &ws.buf)?;

    Ok(())
}

fn main() {
    better_panic::install();

    let matches = clap_app!(lancelot =>
        (author: "Willi Ballenthin <willi.ballenthin@gmail.com>")
        (about: "summarize an executable file's features")
        (@arg verbose: -v --verbose +multiple "log verbose messages")
        (@arg input: +required "path to file to analyze")
    ).get_matches();

    let log_level = match matches.occurrences_of("verbose") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{:5}] {} {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                if log_level == log::LevelFilter::Trace {record.target()} else {""},
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .filter(|metadata| {
            !metadata.target().starts_with("goblin::pe")
        })
        .apply()
        .expect("failed to configure logging");

    if let Err(e) = run(matches.value_of("input").unwrap()) {
        error!("{:?}", e)
    }
}
