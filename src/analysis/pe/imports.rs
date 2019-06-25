use num::Zero;
use num::{FromPrimitive, ToPrimitive};
use std::marker::PhantomData;

use log::{debug};
use goblin::{Object};
use failure::{Error};
use byteorder::{ByteOrder, LittleEndian};

use super::super::super::arch::Arch;
use super::super::super::workspace::Workspace;
use super::super::{Analyzer};


pub struct ImportsAnalyzer<A: Arch> {
    // This Analyzer must have a type parameter for it
    //  to implement Analyzer<A>.
    // however, it doesn't actually use this type itself.
    // so, we use a phantom data marker which has zero type,
    //  to ensure there is not an unused type parameter,
    //  which is a compile error.
    _phantom: PhantomData<A>,
}

impl<A: Arch> ImportsAnalyzer<A> {
    pub fn new() -> ImportsAnalyzer<A> {
        ImportsAnalyzer {
            _phantom: PhantomData {},
        }
    }
}


struct ImageImportDescriptor<A: Arch> {
    original_first_thunk: A::RVA,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: A::RVA,
    first_thunk: A::RVA,
}


impl<A: Arch> ImageImportDescriptor<A> {
    fn is_empty(&self) -> bool {
        self.original_first_thunk == A::RVA::zero() &&
            self.time_date_stamp == 0x0 &&
            self.forwarder_chain == 0x0 &&
            self.name == A::RVA::zero() &&
            self.first_thunk == A::RVA::zero()
    }
}

impl<A: Arch> std::fmt::Debug for ImageImportDescriptor<A>{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IMAGE_IMPORT_DESCRIPTOR(FT: {:#x} OFT: {:#x} name: {:#x})",
               self.first_thunk,
               self.original_first_thunk,
               self.name
        )
    }
}


fn read_image_import_descriptor<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> Result<ImageImportDescriptor<A>, Error> {
    let buf = ws.read_bytes(rva, 5 * 4)?;

    // these fields are all u32, even on 64-bit
    let entries: Vec<u32> = buf
        .chunks_exact(0x4)
        .map(|b| LittleEndian::read_u32(b))
        .collect();

    Ok(ImageImportDescriptor {
        original_first_thunk: A::RVA::from_u32(entries[0]).unwrap(),
        time_date_stamp: entries[1],
        forwarder_chain: entries[2],
        name: A::RVA::from_u32(entries[3]).unwrap(),
        first_thunk: A::RVA::from_u32(entries[4]).unwrap(),
    })
}


enum ImageThunkData<A: Arch> {
    Function(A::RVA),
    Ordinal(u32),
}


fn read_image_thunk_data<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> Result<ImageThunkData<A>, Error> {
    // see: https://reverseengineering.stackexchange.com/a/13387/17194
    let thunk = ws.read_rva(rva)?;
    let v = thunk.to_i64().unwrap();
    if v & (1 << (A::get_bits() - 1)) > 0x0 {
        // MSB is set, this is an ordinal
        Ok(ImageThunkData::Ordinal((v & 0xFFFF) as u32))
    } else {
        Ok(ImageThunkData::Function(thunk))
    }
}


struct ImageImportByName {
    hint: u16,
    name: String,
}


impl std::fmt::Debug for ImageImportByName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IMAGE_IMPORT_BY_NAME(hint: {:#x} name: {})",
               self.hint,
               self.name
        )
    }
}


fn read_image_import_by_name<A: Arch + 'static>(ws: &Workspace<A>, rva: A::RVA) -> Result<ImageImportByName, Error> {
    Ok(ImageImportByName {
        hint: ws.read_u16(rva)?,
        name: ws.read_utf8(rva + A::RVA::from_usize(2).unwrap())?,
    })
}


impl<A: Arch + 'static> Analyzer<A> for ImportsAnalyzer<A> {
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
    /// let mut ws = Workspace::<Arch64>::from_bytes("k32.dll", &get_buf(Rsrc::K32))
    ///    .disable_analysis()
    ///    .load().unwrap();
    /// let anal = ImportsAnalyzer::<Arch64>::new();
    /// anal.analyze(&mut ws).unwrap();
    /// assert_eq!(ws.get_symbol(0x77448).unwrap(), "api-ms-win-core-appcompat-l1-1-1.dll!BaseReadAppCompatDataForProcess");
    /// ```
    fn analyze(&self, ws: &mut Workspace<A>) -> Result<(), Error> {
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

            A::RVA::from_u32(import_directory.virtual_address).unwrap()
        };

        debug!("import directory: {:#x}", import_directory);

        let mut symbols: Vec<(A::RVA, String)> = vec![];

        let psize: usize = A::get_ptr_size() as usize;
        for i in 0..std::usize::MAX {
            //
            //  0x0                    0x14
            //  +-------------------------+           0x0          ptrsize
            //  | IMAGE_IMPORT_DESCRIPTOR | --------> +------------------+
            //  +-------------------------+ \         | IMAGE_THUNK_DATA | -------> +----------------------+
            //  | ...                     |  |        +------------------+          | IMAGE_IMPORT_BY_NAME |
            //  +-------------------------+  |        | ...              |          +----------------------+
            //  | 00 00 00 00 00 00 000   |  |        +------------------+          | hint u16             |
            //  +-------------------------+  |        | 00 00 00 00 00   |          | name ascii           |
            //                               |        +------------------+          +----------------------+
            //                               |
            //                               +> dll-name (ascii)
            let import_descriptor_rva = import_directory + A::RVA::from_usize(i * 0x14).unwrap();
            let import_descriptor = read_image_import_descriptor(ws, import_descriptor_rva)?;
            if import_descriptor.is_empty() {
                break;
            }

            let dll_name = ws.read_utf8(import_descriptor.name)?;
            debug!("{:?} -> {}", import_descriptor, dll_name);

            for j in 0..std::usize::MAX {
                // the First Thunk (FT) is the pointer that will be overwritten upon load.
                // entries here may not point to the IMAGE_IMPORT_BY_NAME.
                let first_thunk = import_descriptor.first_thunk + A::RVA::from_usize(j * psize).unwrap();
                // the Original First Thunk (OFT) remains constant, and points to the IMAGE_IMPORT_BY_NAME.
                // FT and OFT are parallel arrays.
                let image_thunk_data_rva = import_descriptor.original_first_thunk + A::RVA::from_usize(j * psize).unwrap();
                match read_image_thunk_data(ws, image_thunk_data_rva)? {
                    ImageThunkData::Function(rva) => {
                        if rva == A::RVA::zero() {
                            break;
                        } else {
                            let imp = read_image_import_by_name(ws, rva)?;
                            debug!("{:?}", imp);

                            symbols.push((first_thunk, format!("{}!{}", dll_name, imp.name)))
                        }
                    },
                    ImageThunkData::Ordinal(ord) => {
                        symbols.push((first_thunk, format!("{}!#{}", dll_name, ord)))
                    },
                };
            }
        }

        for (rva, name) in symbols.iter() {
            debug!("import: {:#x} -> {}", rva, name);
            ws.make_symbol(*rva, name)?;
            ws.analyze()?;
        }

        Ok(())
    }
}
