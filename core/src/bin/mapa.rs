// TODO:
//   - data directories
//   - name sections
//   - list functions
//   - colors
//   - summarize as empty/hex/strings
//   - section entropy
//   - resource parsing
extern crate log;
extern crate lancelot;
#[macro_use] extern crate lazy_static;

use std::collections::HashMap;
use std::env;
use std::ops::Range;
use std::process;

use better_panic;
use failure::{Error, Fail};
use goblin::Object;
use log::{error, info, trace};
use regex::bytes::Regex;

use lancelot::util;
use lancelot::workspace::Workspace;

#[derive(Debug, Fail)]
pub enum MainError {
    #[fail(display = "foo")]
    Foo,
    #[fail(display = "Invalid PE file")]
    InvalidFile,
    #[fail(display = "Unmapped address")]
    UnmappedVA,
}

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments: provide `mapa.exe /path/to/input.exe`");
        }

        let filename = args[1].clone();
        trace!("config: parsed filename: {:?}", filename);

        Ok(Config { filename })
    }
}

pub fn setup_logging(_args: &Config) {
    simplelog::TermLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to setup logging");
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
    ImportAddressTable,
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
            Structure::ImportAddressTable => write!(f, "import address table"),
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
        static ref re: Regex = Regex::new("[ -~]{4,}").unwrap();
    }

    re.captures_iter(buf)
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
        static ref re: Regex = Regex::new("([ -~]\x00){4,}").unwrap();
    }

    re.captures_iter(buf)
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

    fn render(&self, buf: &[u8]) -> Result<Vec<String>, Error> {
        let mut ret: Vec<String> = vec![];

        if let Structure::String(s) = &self.structure {
            ret.push(format!("    {:#08x} string \"{}\"", self.range.start, s));
        } else {
            // ref: https://www.fileformat.info/info/unicode/block/box_drawing/list.htm
            ret.push(format!("┌── {:#08x} {} ────────", self.range.start, self.structure));

            match &self.structure {
                Structure::IMAGE_SECTION_HEADER(_, _)
                | Structure::IMAGE_DOS_HEADER
                | Structure::Signature
                | Structure::IMAGE_FILE_HEADER
                | Structure::IMAGE_OPTIONAL_HEADER
                => {
                    // render hexdump
                    let region = &buf[self.range.start as usize..self.range.end as usize];
                    for line in lancelot::util::hexdump(region,
                                                        self.range.start as usize).split("\n") {
                        if line != "" {
                            ret.push(format!("│   {}", line))
                        }
                    }
                },
                _ => {
                    // render children
                    for (i, child) in self.children.iter().enumerate() {
                        for line in child.render(buf)?.iter() {
                            ret.push(format!("│  {}", line))
                        }
                        if i < self.children.len() - 1 {
                            match (&self.children[i].structure,  &self.children[i + 1].structure) {
                                (Structure::String(_), Structure::String(_)) => {},
                                _ => {ret.push(format!("│")) }
                            }
                        }
                    }
                }
            }

            ret.push(format!("└── {:#08x} ────────────────────────", self.range.end));
        }

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
        directories.push((Box::new(|| *opt.data_directories.get_import_table()), Structure::ImportTable));
        directories.push((Box::new(|| *opt.data_directories.get_resource_table()), Structure::ResourceTable));
        directories.push((Box::new(|| *opt.data_directories.get_exception_table()), Structure::ExceptionTable));
        directories.push((Box::new(|| *opt.data_directories.get_certificate_table()), Structure::CertificateTable));
        directories.push((Box::new(|| *opt.data_directories.get_base_relocation_table()), Structure::BaseRelocationTable));
        directories.push((Box::new(|| *opt.data_directories.get_debug_table()), Structure::DebugData));
        directories.push((Box::new(|| *opt.data_directories.get_tls_table()), Structure::TlsTable));
        directories.push((Box::new(|| *opt.data_directories.get_load_config_table()), Structure::LoadConfigTable));
        directories.push((Box::new(|| *opt.data_directories.get_bound_import_table()), Structure::BoundImportTable));
        directories.push((Box::new(|| *opt.data_directories.get_import_address_table()), Structure::ImportAddressTable));
        directories.push((Box::new(|| *opt.data_directories.get_delay_import_descriptor()), Structure::DelayImportDescriptor));
        directories.push((Box::new(|| *opt.data_directories.get_clr_runtime_header()), Structure::ClrRuntimeHeader));

        for (f, structure) in directories.iter() {
            if let Some(dir) = f() {
                if let Ok(pfile) = va2pfile(&pe, dir.virtual_address) {
                    println!("{:#x} {:#x} {}", pfile, pfile + dir.size, structure);
                    locations.insert(
                        Range {
                            start: pfile as u64,
                            end: (pfile + dir.size) as u64,
                        },
                        structure.clone(),
                    );
                }
            }
        }
    }

    for (loc, string) in find_strings(&ws.buf).iter() {
        locations.insert(Range {
            start: loc.start as u64,
            end: loc.end as u64,
        }, Structure::String(string.clone()));
    }

    Ok(Map {
        locations
    })
}

fn va2pfile(pe: &goblin::pe::PE, va: u32) -> Result<u32, Error> {
    for section in pe.sections.iter() {
        if va >= section.virtual_address && va < section.virtual_address + section.virtual_size {
            let offset = va - section.virtual_address;
            return Ok(section.pointer_to_raw_data + offset);
        }
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

pub fn run(args: &Config) -> Result<(), Error> {
    info!("filename: {:?}", args.filename);

    let ws = Workspace::from_file(&args.filename)?.load()?;
    let map = compute_map(&ws)?;
    render_map(&map, &ws.buf)?;

    Ok(())
}

fn main() {
    better_panic::install();

    let args = Config::from_args(env::args()).unwrap_or_else(|err| {
        eprintln!("error parsing arguments: {}", err);
        process::exit(1);
    });

    setup_logging(&args);

    if let Err(e) = run(&args) {
        error!("{:?}", e)
    }
}
