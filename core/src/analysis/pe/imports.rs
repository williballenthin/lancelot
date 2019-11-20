use byteorder::{ByteOrder, LittleEndian};
use failure::Error;
use goblin::Object;
use log::debug;

use super::super::{
    super::{arch::RVA, loader::Permissions, workspace::Workspace},
    Analyzer,
};

pub struct ImportsAnalyzer {}

impl ImportsAnalyzer {
    pub fn new() -> ImportsAnalyzer {
        ImportsAnalyzer {}
    }
}

pub struct ImageImportDescriptor {
    pub original_first_thunk: RVA,
    pub time_date_stamp:      u32,
    pub forwarder_chain:      u32,
    pub name:                 RVA,
    pub first_thunk:          RVA,
}

impl ImageImportDescriptor {
    pub fn is_empty(&self) -> bool {
        self.original_first_thunk == RVA(0x0)
            && self.time_date_stamp == 0x0
            && self.forwarder_chain == 0x0
            && self.name == RVA(0x0)
            && self.first_thunk == RVA(0x0)
    }
}

impl std::fmt::Debug for ImageImportDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "IMAGE_IMPORT_DESCRIPTOR(FT: {} OFT: {} name: {})",
            self.first_thunk, self.original_first_thunk, self.name
        )
    }
}

pub fn read_image_import_descriptor(ws: &Workspace, rva: RVA) -> Result<ImageImportDescriptor, Error> {
    let buf = ws.read_bytes(rva, 5 * 4)?;

    // these fields are all u32, even on 64-bit
    let entries: Vec<u32> = buf.chunks_exact(0x4).map(|b| LittleEndian::read_u32(b)).collect();

    Ok(ImageImportDescriptor {
        original_first_thunk: RVA::from(entries[0] as i64),
        time_date_stamp:      entries[1],
        forwarder_chain:      entries[2],
        name:                 RVA::from(entries[3] as i64),
        first_thunk:          RVA::from(entries[4] as i64),
    })
}

pub enum ImageThunkData {
    Function(RVA),
    Ordinal(u32),
}

pub fn read_image_thunk_data(ws: &Workspace, rva: RVA) -> Result<ImageThunkData, Error> {
    // see: https://reverseengineering.stackexchange.com/a/13387/17194
    let thunk = ws.read_rva(rva)?;
    let v: u64 = thunk.into();

    let ordinal_mask: u64 = (1 as u64) << ((ws.loader.get_arch().get_pointer_size() * 8) - 1);
    if v & ordinal_mask > 0x0 {
        // MSB is set, this is an ordinal
        Ok(ImageThunkData::Ordinal((v & 0xFFFF) as u32))
    } else {
        Ok(ImageThunkData::Function(thunk))
    }
}

pub struct ImageImportByName {
    pub hint: u16,
    pub name: String,
}

impl std::fmt::Debug for ImageImportByName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IMAGE_IMPORT_BY_NAME(hint: {} name: {})", self.hint, self.name)
    }
}

pub fn read_image_import_by_name(ws: &Workspace, rva: RVA) -> Result<ImageImportByName, Error> {
    Ok(ImageImportByName {
        hint: ws.read_u16(rva)?,
        name: ws.read_utf8(rva + RVA::from(2))?,
    })
}

pub fn read_best_thunk_data(
    ws: &Workspace,
    original_first_thunk: RVA,
    first_thunk: RVA,
) -> Result<ImageThunkData, Error> {
    // the Original First Thunk (OFT) remains constant, and points to the
    // IMAGE_IMPORT_BY_NAME. FT and OFT are parallel arrays.

    // the First Thunk (FT) is the pointer that will be overwritten upon load.
    // entries here may not point to the IMAGE_IMPORT_BY_NAME.
    //
    // in practice, using this array works better, as some OFT entries may be empty.
    // see: be24e9d47cfe588a8ced0ac3e453d390 hotfix2.exe
    //
    // however, this doesn't work if the PE has been dumped from memory
    // (and the FTs fixed up).
    match read_image_thunk_data(ws, first_thunk) {
        Ok(ImageThunkData::Function(rva)) => {
            if rva == RVA(0x0) {
                // end of array, this is a valid entry, return it.
                Ok(ImageThunkData::Function(rva))
            } else if ws.probe(rva, 1, Permissions::R) {
                // seems to be a valid address, return it.
                Ok(ImageThunkData::Function(rva))
            } else {
                // invalid address, so let's try from the OFT array
                // this might happen if we're dealing with a PE that was dumped from memory.
                // the FT might have been overwritten, so we need to use the OFT, instead.
                read_image_thunk_data(ws, original_first_thunk)
            }
        }
        Ok(ImageThunkData::Ordinal(ord)) => {
            // ordinal is a valid entry, return it.
            Ok(ImageThunkData::Ordinal(ord))
        }
        Err(_) => {
            // fall back to the OFT array
            read_image_thunk_data(ws, original_first_thunk)
        }
    }
}

impl Analyzer for ImportsAnalyzer {
    fn get_name(&self) -> String {
        "PE imports analyzer".to_string()
    }

    /// ```
    /// use lancelot::rsrc::*;
    /// use lancelot::arch::*;
    /// use lancelot::analysis::Analyzer;
    /// use lancelot::workspace::Workspace;
    /// use lancelot::analysis::pe::ImportsAnalyzer;
    ///
    /// let mut ws = Workspace::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = ImportsAnalyzer::new();
    /// anal.analyze(&mut ws).unwrap();
    /// assert_eq!(ws.get_symbol(RVA(0x77448)).unwrap(), "api-ms-win-core-appcompat-l1-1-1.dll!BaseReadAppCompatDataForProcess");
    /// ```
    fn analyze(&self, ws: &mut Workspace) -> Result<(), Error> {
        let import_directory = {
            let pe = match Object::parse(&ws.buf) {
                Ok(Object::PE(pe)) => pe,
                _ => panic!("can't analyze unexpected format"),
            };

            let opt_header = match pe.header.optional_header {
                Some(opt_header) => opt_header,
                _ => return Ok(()),
            };

            let import_directory = match opt_header.data_directories.get_import_table() {
                Some(import_directory) => import_directory,
                _ => return Ok(()),
            };

            RVA::from(import_directory.virtual_address as i64)
        };

        debug!("found import directory: {}", import_directory);

        let mut symbols: Vec<(RVA, String)> = vec![];

        let psize: usize = ws.loader.get_arch().get_pointer_size() as usize;
        for i in 0..std::usize::MAX {
            //
            //  0x0                    0x14
            //  +-------------------------+           0x0          ptrsize
            //  | IMAGE_IMPORT_DESCRIPTOR | --------> +------------------+
            //  +-------------------------+ \         | IMAGE_THUNK_DATA | ------->
            // +----------------------+  | ...                     |  |
            // +------------------+          | IMAGE_IMPORT_BY_NAME |
            //  +-------------------------+  |        | ...              |
            // +----------------------+  | 00 00 00 00 00 00 000   |  |
            // +------------------+          | hint u16             |
            //  +-------------------------+  |        | 00 00 00 00 00   |          | name
            // ascii           |                               |
            // +------------------+          +----------------------+
            //                               |
            //                               +> dll-name (ascii)
            let import_descriptor_rva = import_directory + RVA::from(i * 0x14);
            let import_descriptor = read_image_import_descriptor(ws, import_descriptor_rva)?;
            if import_descriptor.is_empty() {
                break;
            }

            let dll_name = ws.read_utf8(import_descriptor.name)?;
            debug!("found {:?} -> {}", import_descriptor, dll_name);

            for j in 0..std::usize::MAX {
                // the Original First Thunk (OFT) remains constant, and points to the
                // IMAGE_IMPORT_BY_NAME. FT and OFT are parallel arrays.
                let original_first_thunk = import_descriptor.original_first_thunk + RVA::from(j * psize);

                // the First Thunk (FT) is the pointer that will be overwritten upon load.
                // entries here may not point to the IMAGE_IMPORT_BY_NAME.
                let first_thunk = import_descriptor.first_thunk + RVA::from(j * psize);

                match read_best_thunk_data(ws, original_first_thunk, first_thunk)? {
                    ImageThunkData::Function(rva) => {
                        if rva == RVA(0x0) {
                            // end of array
                            break;
                        } else {
                            let imp = read_image_import_by_name(ws, rva)?;
                            debug!("found {:?}", imp);
                            symbols.push((first_thunk, format!("{}!{}", dll_name, imp.name)))
                        }
                    }
                    ImageThunkData::Ordinal(ord) => symbols.push((first_thunk, format!("{}!#{}", dll_name, ord))),
                };
            }
        }

        for (rva, name) in symbols.iter() {
            debug!("found import: {} -> {}", rva, name);
            ws.make_symbol(*rva, name)?;
            ws.analyze()?;
        }

        Ok(())
    }
}
