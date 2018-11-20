extern crate log;
extern crate simplelog;

use goblin::pe::PE;
use goblin::Object;
use log::{debug, error, info, trace};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::prelude::*;
use zydis;

// TODO: this really shouldn't be public. only for testing.
// TODO: what is the `cfg(doctest)` setting?
//#[cfg(test)]
pub mod rsrc;

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn from_args(args: env::Args) -> Result<Config, &'static str> {
        let args: Vec<String> = args.collect();

        if args.len() < 2 {
            return Err("not enough arguments");
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

#[derive(Debug)]
pub enum Error {
    FileAccess,
    FileFormat,
    NotImplemented,
    ValueError,
}

/// Round the given value up to the next multiple of the given base.
///
/// # Panics
///
///   - Base `b` must be at least `2`.
///
/// # Examples
///
/// ```
/// use lancelot::*;
/// assert_eq!(align(0, 2), 0);
/// assert_eq!(align(1, 2), 2);
/// assert_eq!(align(2, 2), 2);
/// assert_eq!(align(3, 2), 4);
/// assert_eq!(align(4, 2), 4);
/// ```
pub fn align(i: usize, b: usize) -> usize {
    if b < 2 {
        panic!("base `b` must be at least: 2");
    }
    let rem = i % b;
    if rem == 0 {
        i
    } else {
        i + (b - rem)
    }
}

pub fn hexdump_ascii(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' {
        b as char
    } else {
        '.'
    }
}

pub fn hexdump(buf: &[u8], offset: usize) -> String {
    // 01234567:  00 01 02 03 04 05 06 07  ...............
    // <prefix>   <hex col>                <ascii col>

    let padding = "  ";

    let padding_size = 2;
    let hex_col_size = 3;
    let ascii_col_size = 1;
    let prefix_size = 8 + 1;
    let newline_size = 1;
    let line_size = prefix_size
        + padding_size
        + 16 * hex_col_size
        + padding_size
        + 16 * ascii_col_size
        + newline_size;
    let line_count = align(buf.len(), 0x10) / 0x10;

    let mut ret = String::with_capacity(line_count * line_size);

    let mut line = String::with_capacity(line_size);
    let mut remaining_count = buf.len();
    for line_index in 0..line_count {
        let line_elem_count = 0x10.min(remaining_count);
        let padding_elem_count = 0x10 - line_elem_count;

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        // ^^^^^^^^^
        line.push_str(format!("{:08x}:", offset + 0x10 * line_index).as_str());

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //          ^^
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //            ^^^
        for elem in &buf[line_index..line_index + line_elem_count] {
            line.push_str(format!("{:02x} ", elem).as_str());
        }
        for _ in 0..padding_elem_count {
            line.push_str("   ");
        }

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                   ^^
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                     ^
        for elem in &buf[line_index..line_index + line_elem_count] {
            line.push(hexdump_ascii(*elem))
        }
        for _ in 0..padding_elem_count {
            line.push(' ');
        }
        line.push_str(padding);

        // 01234567:  00 01 02 03 04 05 06 07  ...............
        //                                                    ^
        line.push('\n');

        ret.push_str(line.as_str());
        line.truncate(0x0);
        remaining_count -= line_elem_count;
    }

    ret
}

fn foo(ws: &Workspace) -> Result<(), Error> {
    if let Object::PE(pe) = ws.get_obj().unwrap() {
        info!("module: {}", pe.name.unwrap_or("(unknown)"));

        info!("bitness: {}", if pe.is_64 { "64" } else { "32" });
        info!("image base: 0x{:x}", pe.image_base);
        info!("entry rva: 0x{:x}", pe.entry);

        // like:
        //
        //     sections:
        //       - .text
        //         raw size:     0x18aa00
        //         virtual size: 0x18a9a8
        info!("sections:");
        for section in ws.sections.iter() {
            info!("  - {}", section.name);
            info!("    virtual address: 0x{:x}", section.addr);
            info!("    virtual size: 0x{:x}", section.buf.len());

            info!(
                "\n{}",
                hexdump(&section.buf[..0x1C], pe.image_base + section.addr as usize)
            );

            let decoder =
                zydis::Decoder::new(zydis::MachineMode::Long64, zydis::AddressWidth::_64).unwrap();
            let insns: Vec<_> = section
                .buf
                .par_windows(0x10)
                .map(|ibuf| decoder.decode(ibuf))
                .collect();

            info!("total instructions: {}", insns.len());

            info!(
                "successful disassembles: {}",
                insns.par_iter().filter(|insn| insn.is_ok()).count()
            );

            info!(
                "valid instructions: {}",
                insns
                    .par_iter()
                    .filter(|insn| match insn {
                        Ok(Some(_)) => true,
                        _ => false,
                    })
                    .count()
            );
        }
    }

    Ok(())
}

pub fn read_file(filename: &str) -> Result<Vec<u8>, Error> {
    debug!("read_file: {:?}", filename);

    let mut buf = Vec::new();
    {
        debug!("reading file: {}", filename);
        let mut f = match fs::File::open(filename) {
            Ok(f) => f,
            Err(_) => {
                error!("failed to open file: {}", filename);
                return Err(Error::FileAccess);
            }
        };
        let bytes_read = match f.read_to_end(&mut buf) {
            Ok(c) => c,
            Err(_) => {
                error!("failed to read entire file: {}", filename);
                return Err(Error::FileAccess);
            }
        };
        debug!("read {} bytes", bytes_read);
        if bytes_read < 0x10 {
            error!("file too small: {}", filename);
            return Err(Error::FileFormat);
        }
    }

    Ok(buf)
}

pub struct Section {
    pub name: String,
    pub addr: u32,
    pub buf: Vec<u8>,
    pub insns: Vec<Option<zydis::ffi::DecodedInstruction>>,
}

pub struct Workspace {
    pub filename: String,
    pub buf: Vec<u8>,
    pub sections: Vec<Section>,
}

impl Workspace {
    /// Parse the given file into its object.
    ///
    /// # Errors
    ///   - `Error::FileFormat`: when not able to be parsed by Goblin.
    ///
    /// # Examples
    ///
    /// ```
    /// use goblin::Object;
    /// use matches::matches;
    /// use lancelot::rsrc::*;
    /// let ws = get_workspace(Rsrc::K32);
    /// assert!(matches!(ws.get_obj().unwrap(), Object::PE(_)));
    /// ```
    ///
    /// you might be tempted to maintain a method `get_pe`,
    /// however, i don't think this is a good idea:
    /// its fragile because the file type may not be PE.
    /// therefore, force clients to be explicit:
    ///
    /// ```
    /// use goblin::Object;
    /// use lancelot::rsrc::*;
    /// let ws = get_workspace(Rsrc::K32);
    /// if let Object::PE(_) = ws.get_obj().unwrap() {
    ///     // everyone is happy!
    /// }
    /// ```
    ///
    /// TODO: demonstrate `Error::FileFormat`.
    pub fn get_obj(&self) -> Result<Object, Error> {
        let obj = match Object::parse(&self.buf) {
            Ok(o) => o,
            Err(e) => {
                error!("failed to parse file: {} error: {:?}", self.filename, e);
                return Err(Error::FileFormat);
            }
        };

        match obj {
            Object::Unknown(_) => {
                error!(
                    "unknown file format, magic: | {:02X} {:02X} | '{}{}' ",
                    self.buf[0],
                    self.buf[1],
                    hexdump_ascii(self.buf[0]),
                    hexdump_ascii(self.buf[1])
                );

                Err(Error::FileFormat)
            }
            _ => Ok(obj),
        }
    }

    pub fn get_pe(&self) -> Result<PE, Error> {
        match self.get_obj()? {
            Object::PE(pe) => {
                return Ok(pe);
            }
            _ => {
                error!("not a PE file");
                return Err(Error::ValueError);
            }
        }
    }

    /// Construct a workspace from the module with the given contents.
    ///
    /// # Errors
    ///   - `Error::FileFormat`: when not able to be parsed by Goblin.
    ///   - `Error::NotImplemented`: when not a PE file.
    ///
    /// # Examples
    ///
    /// ```
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// let buf = get_buf(Rsrc::K32);
    /// let ws = Workspace::from_buf("kernel32.dll", buf).unwrap();
    /// ```
    ///
    /// TODO: demonstrate ELF file behavior.
    /// TODO: demonstrate MachO file behavior.
    /// TODO: demonstrate unknown file behavior.
    pub fn from_buf(filename: &str, buf: Vec<u8>) -> Result<Workspace, Error> {
        let mut ws = Workspace {
            filename: filename.to_string(),
            buf: buf.clone(),
            sections: vec![],
        };

        match ws.get_obj()? {
            Object::PE(pe) => {
                info!("found PE file");

                let machine;
                let mode;
                if pe.is_64 {
                    machine = zydis::MachineMode::Long64;
                    mode = zydis::AddressWidth::_64;
                } else {
                    // TODO: not sure what `LongCompat32` means, vs `Legacy32`.
                    machine = zydis::MachineMode::LongCompat32;
                    mode = zydis::AddressWidth::_32;
                }
                // TODO: save off decoder into workspace.
                let decoder = zydis::Decoder::new(machine, mode).unwrap();

                // TODO: load PE header, too

                ws.sections
                    .extend(pe.sections.iter().map(|section| -> Section {
                        // TODO: i'm sure this can be abused.
                        // TODO: add tests for weird section names.
                        let name = String::from_utf8_lossy(&section.name[..])
                            .into_owned()
                            .trim_end_matches("\u{0}")
                            .trim_end()
                            .to_string();

                        // TODO: figure out if we will work with usize, or u64, or what,
                        // then assert usize is ok.
                        // ref: `usize::max_value()`
                        let mut secbuf = vec![0; align(section.virtual_size as usize, 0x200)];

                        {
                            let secsize = section.size_of_raw_data as usize;
                            let rawbuf = &mut secbuf[..secsize];
                            let pstart = section.pointer_to_raw_data as usize;
                            rawbuf.copy_from_slice(&buf[pstart..pstart + secsize]);
                        }

                        let insns: Vec<_> = secbuf
                            .par_windows(0x10)
                            .map(|ibuf| match decoder.decode(ibuf) {
                                Ok(Some(insn)) => Some(insn),
                                _ => None,
                            })
                            .collect();

                        Section {
                            name: name,
                            addr: section.virtual_address,
                            buf: secbuf,
                            insns: insns,
                        }
                    }));
            }
            Object::Elf(_) => {
                return Err(Error::NotImplemented);
            }
            Object::Mach(_) => {
                return Err(Error::NotImplemented);
            }
            Object::Archive(_) => {
                return Err(Error::NotImplemented);
            }
            Object::Unknown(_) => {
                return Err(Error::NotImplemented);
            }
        }

        Ok(ws)
    }

    /// Construct a workspace from the module at given a file path.
    ///
    /// ```
    /// use lancelot::*;
    /// use lancelot::rsrc::*;
    /// let path = get_path(Rsrc::K32);
    /// // This test resource file is mangled. Needs to be fixed before parsing.
    /// // Otherwise, the following would work:
    /// // let ws = Workspace::from_file(&path).unwrap();
    /// ```
    pub fn from_file(filename: &str) -> Result<Workspace, Error> {
        let buf = read_file(filename)?;
        Workspace::from_buf(filename, buf)
    }
}

pub fn run(args: &Config) -> Result<(), Error> {
    debug!("filename: {:?}", args.filename);
    let ws = Workspace::from_file(&args.filename)?;

    if let Object::PE(_) = ws.get_obj()? {
        foo(&ws).expect("failed to foo");
    }

    Ok(())
}
