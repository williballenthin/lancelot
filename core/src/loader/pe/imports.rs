// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};

use crate::{aspace::AddressSpace, loader::pe::PE, module::Permissions, RVA, VA};

const sizeof_IMAGE_IMPORT_DESCRIPTOR: usize = 0x14;

// ```
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
// ```
#[derive(Clone)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub original_first_thunk: RVA,
    pub time_date_stamp:      u32,
    pub forwarder_chain:      u32,
    pub name:                 RVA,
    pub first_thunk:          RVA,
}

impl IMAGE_IMPORT_DESCRIPTOR {
    pub fn is_empty(&self) -> bool {
        self.original_first_thunk == 0x0
            && self.time_date_stamp == 0x0
            && self.forwarder_chain == 0x0
            && self.name == 0x0
            && self.first_thunk == 0x0
    }

    /// read the name of the DLL into a String.
    pub fn read_name(&self, pe: &PE) -> Result<String> {
        pe.module
            .address_space
            .read_ascii(pe.module.address_space.base_address + self.name, 1)
    }
}

impl std::fmt::Debug for IMAGE_IMPORT_DESCRIPTOR {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "IMAGE_IMPORT_DESCRIPTOR(FT: {:#x} OFT: {:#x} name: {:#x})",
            self.first_thunk, self.original_first_thunk, self.name
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IMAGE_THUNK_DATA {
    Function(RVA),
    Ordinal(u32),
}

#[derive(Clone)]
pub struct IMAGE_IMPORT_BY_NAME {
    pub hint: u16,
    pub name: String,
}

impl std::fmt::Debug for IMAGE_IMPORT_BY_NAME {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "IMAGE_IMPORT_BY_NAME(hint: {} name: {})", self.hint, self.name)
    }
}

/// fetch the VA of the import directory, if it exists.
pub fn get_import_directory(pe: &PE) -> Result<Option<VA>> {
    if let Some(opt) = pe.optional_header {
        if let Some(import_directory) = opt.data_directories.get_import_table() {
            let base_address = pe.module.address_space.base_address;
            return Ok(Some(base_address + import_directory.virtual_address as RVA));
        }
    }
    Ok(None)
}

pub fn read_image_import_descriptor(pe: &PE, va: VA) -> Result<IMAGE_IMPORT_DESCRIPTOR> {
    let buf = pe.module.address_space.read_bytes(va, sizeof_IMAGE_IMPORT_DESCRIPTOR)?;

    // these fields are all u32, even on 64-bit
    let entries: Vec<u32> = buf.chunks_exact(0x4).map(LittleEndian::read_u32).collect();

    Ok(IMAGE_IMPORT_DESCRIPTOR {
        original_first_thunk: entries[0] as RVA,
        time_date_stamp:      entries[1],
        forwarder_chain:      entries[2],
        name:                 entries[3] as RVA,
        first_thunk:          entries[4] as RVA,
    })
}

pub fn read_import_descriptors(pe: &PE, import_directory: VA) -> impl Iterator<Item = IMAGE_IMPORT_DESCRIPTOR> + '_ {
    (0..usize::MAX)
        .map(move |i| import_directory + (i * sizeof_IMAGE_IMPORT_DESCRIPTOR) as RVA)
        .map(move |va| read_image_import_descriptor(pe, va))
        .take_while(|desc| match desc {
            Ok(desc) => !desc.is_empty(),
            Err(_) => false,
        })
        .map(|desc| desc.unwrap())
}

pub fn read_image_thunk_data(pe: &PE, va: VA) -> Result<IMAGE_THUNK_DATA> {
    let psize = pe.module.arch.pointer_size();
    let thunk = pe.module.read_rva_at_va(va)?;

    let ordinal_mask: u64 = 1u64 << ((psize as u64 * 8) - 1);
    if thunk & ordinal_mask > 0x0 {
        // MSB is set, this is an ordinal
        Ok(IMAGE_THUNK_DATA::Ordinal((thunk & 0xFFFF) as u32))
    } else {
        Ok(IMAGE_THUNK_DATA::Function(thunk))
    }
}

pub fn read_best_thunk_data(pe: &PE, original_first_thunk_addr: VA, first_thunk_addr: VA) -> Result<IMAGE_THUNK_DATA> {
    // the Original First Thunk (OFT) remains constant, and points to the
    // IMAGE_IMPORT_BY_NAME. FT and OFT are parallel arrays.

    // the First Thunk (FT) is the pointer that will be overwritten upon load.
    // entries here may not point to the IMAGE_IMPORT_BY_NAME.
    //
    // note: some OFT entries may be empty
    // see: be24e9d47cfe588a8ced0ac3e453d390 hotfix2.exe
    //
    // however, this doesn't work if the PE has been dumped from memory
    // (and the FTs fixed up).

    let ft = read_image_thunk_data(pe, first_thunk_addr);
    let oft = read_image_thunk_data(pe, original_first_thunk_addr);

    if ft.is_err() && oft.is_err() {
        // prefer the OFT errror.
        return oft;
    }

    fn validate_thunk_data(pe: &PE, thunk: IMAGE_THUNK_DATA) -> Result<IMAGE_THUNK_DATA> {
        match thunk {
            IMAGE_THUNK_DATA::Ordinal(_) => Ok(thunk),
            IMAGE_THUNK_DATA::Function(thunk) => {
                if pe.module.probe_rva(thunk, Permissions::R)
                    && pe.module.address_space.relative.read_ascii(thunk + 2, 1).is_ok()
                {
                    // thunk appears to contain a string.
                    // because in a198216798ca38f280dc413f8c57f2c2,
                    // FT contains a non-zero hint, but empty name name.
                    return Ok(IMAGE_THUNK_DATA::Function(thunk));
                }
                Err(crate::loader::pe::PEError::MalformedPEFile("invalid thunk".to_string()).into())
            }
        }
    }

    if let Ok(oft) = oft {
        if let Ok(oft) = validate_thunk_data(pe, oft) {
            return Ok(oft);
        }
    }

    // OFT pointer is not valid
    // or OFT thunk doesn't contain a string
    // so fall back to trying the FT

    if let Ok(ft) = ft {
        if let Ok(ft) = validate_thunk_data(pe, ft) {
            return Ok(ft);
        }
    }

    // FT pointer is not valid
    // or FT thunk doesn't caontain a string
    // neither OFT nor FT are valid, so we're in error territory.

    Err(crate::loader::pe::PEError::MalformedPEFile("invalid FT/OFT entry".to_string()).into())
}

pub fn read_thunks<'a>(
    pe: &'a PE,
    import_descriptor: &'a IMAGE_IMPORT_DESCRIPTOR,
) -> impl Iterator<Item = IMAGE_THUNK_DATA> + 'a {
    let base_address = pe.module.address_space.base_address;
    let psize = pe.module.arch.pointer_size();

    (0..usize::MAX)
        .map(move |i| {
            (
                // the Original First Thunk (OFT) remains constant, and points to the
                // IMAGE_IMPORT_BY_NAME. FT and OFT are parallel arrays.
                base_address + import_descriptor.original_first_thunk + (i * psize) as RVA,
                // the First Thunk (FT) is the pointer that will be overwritten upon load.
                // entries here may not point to the IMAGE_IMPORT_BY_NAME.
                base_address + import_descriptor.first_thunk + (i * psize) as RVA,
            )
        })
        .map(move |(oft, ft)| read_best_thunk_data(pe, oft, ft))
        .take_while(move |thunk| !matches!(thunk, Err(_) | Ok(IMAGE_THUNK_DATA::Function(0x0))))
        .map(move |thunk| thunk.unwrap())
}

pub fn read_image_import_by_name(pe: &PE, va: VA) -> Result<IMAGE_IMPORT_BY_NAME> {
    Ok(IMAGE_IMPORT_BY_NAME {
        hint: pe.module.address_space.read_u16(va)?,
        name: pe.module.address_space.read_ascii(va + 2u64, 1)?,
    })
}
