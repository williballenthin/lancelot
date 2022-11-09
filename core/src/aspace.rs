#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use crate::{
    arch::Arch,
    pagemap::{PageMap, PageMapError},
    RVA, VA,
};

#[derive(Debug, Error)]
pub enum AddressSpaceError {
    #[error("String is too short")]
    StringTooShort,
}

pub trait AddressSpace<T> {
    fn read_into(&self, offset: T, buf: &mut [u8]) -> Result<()>;

    fn read_u8(&self, offset: T) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_into(offset, &mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&self, offset: T) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_into(offset, &mut buf)?;
        Ok(LittleEndian::read_u16(&buf))
    }

    fn read_u32(&self, offset: T) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_into(offset, &mut buf)?;
        Ok(LittleEndian::read_u32(&buf))
    }

    fn read_u64(&self, offset: T) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_into(offset, &mut buf)?;
        Ok(LittleEndian::read_u64(&buf))
    }

    fn read_pointer(&self, arch: Arch, offset: T) -> Result<u64> {
        match arch {
            Arch::X32 => Ok(self.read_u32(offset)? as u64),
            Arch::X64 => Ok(self.read_u64(offset)?),
        }
    }

    fn read_bytes(&self, offset: T, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    /// Create an address space thats backed by this address space,
    /// where all reads are relative to the given address.
    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice>;

    /// Read a NULL-terminated, ASCII-encoded string at the given offset.
    ///
    /// Errors:
    ///
    ///   - PageMapError - if the address is not mapped.
    ///   - std::str::from_utf8 errors - if the data is not valid utf8
    fn read_ascii(&self, offset: T, minimum_length: usize) -> Result<String>;
}

// addresses spaces that support write operations.
// these are really only meant for loaders that apply relocations, etc.
pub trait WritableAddressSpace<T> {
    fn write_u32(&mut self, offset: T, v: u32) -> Result<()>;
    fn write_u64(&mut self, offset: T, v: u64) -> Result<()>;
}

/// An AddressSpace in which data is mapped at or near after a base address,
/// and addressed using positive offsets from this base address.
///
/// For example, this is appropriate for a PE file loaded into memory, using
/// pointers relative to the preferred base address. Here, OEP might be 0x1000.
///
/// Note that this implements `AddressSpace<RVA>` and not `AddressSpace<VA>`.
/// Use `AbsoluteAddressSpace` when you're dealing with absolute addresses
/// (`VA`).
#[derive(Clone)]
pub struct RelativeAddressSpace {
    pub(crate) map: PageMap<u8>,
}

impl RelativeAddressSpace {
    pub fn into_absolute(self, base_address: VA) -> Result<AbsoluteAddressSpace> {
        Ok(AbsoluteAddressSpace {
            base_address,
            relative: self,
        })
    }

    pub fn with_capacity(size: u64) -> RelativeAddressSpace {
        RelativeAddressSpace {
            map: PageMap::with_capacity(size),
        }
    }

    pub fn from_buf(buf: &[u8]) -> RelativeAddressSpace {
        RelativeAddressSpace {
            map: PageMap::from_items(buf),
        }
    }
}

impl AddressSpace<RVA> for RelativeAddressSpace {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        self.map.slice_into(offset, buf)?;
        Ok(())
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        const END_OF_ASCII: u8 = 0x7F;
        const SPACE: u8 = 0x20;
        const TAB: u8 = 0x9;
        const NEWLINE: u8 = 0xA;
        const LINEFEED: u8 = 0xD;

        let buf: Vec<u8> = (offset..std::u64::MAX)
            .map(|offset| self.map.get(offset))
            .take_while(|c| c.is_some())
            .map(|c| c.unwrap())
            .take_while(|&c| c != 0)
            .take_while(|&c| c < END_OF_ASCII && (c >= SPACE || c == TAB || c == NEWLINE || c == LINEFEED))
            .collect();

        if buf.len() < minimum_length {
            return Err(AddressSpaceError::StringTooShort.into());
        }

        Ok(String::from_utf8(buf)?)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

impl WritableAddressSpace<RVA> for RelativeAddressSpace {
    fn write_u32(&mut self, offset: RVA, v: u32) -> Result<()> {
        const PAGE_SIZE: u64 = 0x1000;

        let (page_address, page_offset) = if offset % PAGE_SIZE != 0 {
            (
                crate::util::align(offset, PAGE_SIZE) - PAGE_SIZE,
                (offset % PAGE_SIZE) as usize,
            )
        } else {
            (offset, 0x0usize)
        };

        if page_offset >= PAGE_SIZE as usize - std::mem::size_of::<u32>() {
            panic!("cannot split write");
        }

        // compute the byte-wise u32 representation
        let mut src = [0u8; std::mem::size_of::<u32>()];
        LittleEndian::write_u32(&mut src, v);

        // get the existing page
        let mut page = [0u8; PAGE_SIZE as usize];
        self.map.slice_into(page_address, &mut page[..])?;

        // update the page
        let dst = &mut page[page_offset..page_offset + std::mem::size_of::<u32>()];
        dst.copy_from_slice(&src[..]);

        // write back
        self.map.write(page_address, &page)
    }

    fn write_u64(&mut self, offset: RVA, v: u64) -> Result<()> {
        const PAGE_SIZE: u64 = 0x1000;

        let (page_address, page_offset) = if offset % PAGE_SIZE != 0 {
            (
                crate::util::align(offset, PAGE_SIZE) - PAGE_SIZE,
                (offset % PAGE_SIZE) as usize,
            )
        } else {
            (offset, 0x0usize)
        };

        if page_offset >= PAGE_SIZE as usize - std::mem::size_of::<u64>() {
            panic!("cannot split write");
        }

        // compute the byte-wise u32 representation
        let mut src = [0u8; std::mem::size_of::<u64>()];
        LittleEndian::write_u64(&mut src, v);

        // get the existing page
        let mut page = [0u8; PAGE_SIZE as usize];
        self.map.slice_into(page_address, &mut page[..])?;

        // update the page
        let dst = &mut page[page_offset..page_offset + std::mem::size_of::<u64>()];
        dst.copy_from_slice(&src[..]);

        // write back
        self.map.write(page_address, &page)
    }
}

// its annoying that we have to do this.
// but because in order to `.slice` we need a reference to the inner aspace,
// then aspace references must also implement aspace.
impl AddressSpace<RVA> for &RelativeAddressSpace {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        (*self).read_into(offset, buf)
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        (*self).read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        (*self).slice(offset)
    }
}

impl WritableAddressSpace<RVA> for &mut RelativeAddressSpace {
    fn write_u32(&mut self, offset: RVA, v: u32) -> Result<()> {
        (*self).write_u32(offset, v)
    }

    fn write_u64(&mut self, offset: RVA, v: u64) -> Result<()> {
        (*self).write_u64(offset, v)
    }
}

/// An AddressSpace in which (mostly) contiguous data is mapped at a base
/// address, is addressed using absolute pointers (relative to 0x0).
///
/// For example, this is appropriate for a PE file loaded into memory at its
/// preferred base address, using pointers relative to 0x0. Here, OEP might be
/// 0x401000.
///
/// Internally, this is a `RelativeAddressSpace` + a base address.
/// So, its not a good fit for multiple modules that may be mapped different
/// places. Probably want to implement `SparseAddressSpace` (collection of
/// `AbsoluteAddressSpace`s)  for this.
///
/// Note that this implements `AddressSpace<VA>` and not `AddressSpace<RVA>`.
/// Use `RelativeAddressSpace` when you're dealing with relative addresses
/// (`RVA`).
#[derive(Clone)]
pub struct AbsoluteAddressSpace {
    pub base_address: VA,

    /// The inner relative address space with data mapped at `base_address`.
    /// Its ok to reach into this address space if you've got RVAs relative to
    /// `base_address`.
    pub relative: RelativeAddressSpace,
}

impl AbsoluteAddressSpace {}

impl AddressSpace<VA> for AbsoluteAddressSpace {
    fn read_into(&self, offset: VA, buf: &mut [u8]) -> Result<()> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.read_into((offset - self.base_address) as RVA, buf)
    }

    fn read_ascii(&self, offset: VA, minimum_length: usize) -> Result<String> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative
            .read_ascii((offset - self.base_address) as RVA, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

impl WritableAddressSpace<VA> for AbsoluteAddressSpace {
    fn write_u32(&mut self, offset: VA, v: u32) -> Result<()> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.write_u32((offset - self.base_address) as RVA, v)
    }

    fn write_u64(&mut self, offset: VA, v: u64) -> Result<()> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.write_u64((offset - self.base_address) as RVA, v)
    }
}

impl AddressSpace<VA> for &AbsoluteAddressSpace {
    fn read_into(&self, offset: VA, buf: &mut [u8]) -> Result<()> {
        (*self).read_into(offset, buf)
    }

    fn read_ascii(&self, offset: VA, minimum_length: usize) -> Result<String> {
        (*self).read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        (*self).slice(offset)
    }
}

impl WritableAddressSpace<VA> for &mut AbsoluteAddressSpace {
    fn write_u32(&mut self, offset: VA, v: u32) -> Result<()> {
        (*self).write_u32(offset, v)
    }

    fn write_u64(&mut self, offset: VA, v: u64) -> Result<()> {
        (*self).write_u64(offset, v)
    }
}

pub struct AddressSpaceSlice<'a> {
    /// offset from the start of the underlying aspace that this slice begins
    base_address: RVA,
    inner:        Box<dyn AddressSpace<u64> + 'a>,
}

impl<'a> AddressSpace<RVA> for AddressSpaceSlice<'a> {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        let offset = self.base_address + offset;
        self.inner.read_into(offset, buf)
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        let offset = self.base_address + offset;
        self.inner.read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

// note that slices don't support writing at the moment

impl<'a> AddressSpace<RVA> for &AddressSpaceSlice<'a> {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        (*self).read_into(offset, buf)
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        (*self).read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice> {
        (*self).slice(offset)
    }
}
