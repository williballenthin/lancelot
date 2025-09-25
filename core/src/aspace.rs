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
    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>>;

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
    fn write(&mut self, addr: T, v: &[u8]) -> Result<()>;

    fn write_u16(&mut self, addr: T, v: u16) -> Result<()> {
        let mut src = [0u8; std::mem::size_of::<u16>()];
        LittleEndian::write_u16(&mut src, v);

        self.write(addr, &src[..])
    }

    fn write_u32(&mut self, addr: T, v: u32) -> Result<()> {
        let mut src = [0u8; std::mem::size_of::<u32>()];
        LittleEndian::write_u32(&mut src, v);

        self.write(addr, &src[..])
    }

    fn write_i32(&mut self, addr: T, v: i32) -> Result<()> {
        let mut src = [0u8; std::mem::size_of::<i32>()];
        LittleEndian::write_i32(&mut src, v);

        self.write(addr, &src[..])
    }

    fn write_u64(&mut self, addr: T, v: u64) -> Result<()> {
        let mut src = [0u8; std::mem::size_of::<u64>()];
        LittleEndian::write_u64(&mut src, v);

        self.write(addr, &src[..])
    }

    fn write_i64(&mut self, addr: T, v: i64) -> Result<()> {
        let mut src = [0u8; std::mem::size_of::<i64>()];
        LittleEndian::write_i64(&mut src, v);

        self.write(addr, &src[..])
    }
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

        let buf: Vec<u8> = (offset..u64::MAX)
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

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SHIFT: usize = 12;
pub const PAGE_MASK: u64 = 0xFFF;

pub fn is_page_aligned(va: VA) -> bool {
    va & PAGE_MASK == 0x0
}

pub fn page_address(va: VA) -> u64 {
    (va >> PAGE_SHIFT) << PAGE_SHIFT
}

pub fn page_offset(va: VA) -> usize {
    (va & PAGE_MASK) as usize
}

impl WritableAddressSpace<RVA> for RelativeAddressSpace {
    fn write(&mut self, addr: RVA, buf: &[u8]) -> Result<()> {
        assert!(buf.len() <= PAGE_SIZE);

        let end_addr = addr + buf.len() as u64;
        if page_address(addr) != page_address(end_addr) && !is_page_aligned(end_addr) {
            // uncommon case: split write across two pages
            // guaranteed to only be two pages due to size assertion above.
            let write_size: usize = buf.len();
            let page_offset = page_offset(addr);
            let first_size = PAGE_SIZE - page_offset;
            let second_size = write_size - first_size;

            // first page
            {
                // get the existing page
                let mut page = [0u8; PAGE_SIZE];
                self.map.slice_into(page_address(addr), &mut page[..])?;

                // update the page
                // changes will be until the end of the page (and overflow into next page)
                let dst = &mut page[page_offset..];
                dst.copy_from_slice(&buf[0..first_size]);

                // write back
                self.map.write(page_address(addr), &page)?;
            }

            // second page
            {
                // get the existing page
                let mut page = [0u8; PAGE_SIZE];
                self.map
                    .slice_into(page_address(addr) + PAGE_SIZE as u64, &mut page[..])?;

                // update the page
                // changes will be from page address 0, because it overflows from prior page.
                let dst = &mut page[0..second_size];
                dst.copy_from_slice(&buf[first_size..]);

                // write back
                self.map.write(page_address(addr) + PAGE_SIZE as u64, &page)?;
            }
        } else {
            // common case: all data in single page

            // get the existing page
            let mut page = [0u8; PAGE_SIZE];
            self.map.slice_into(page_address(addr), &mut page[..])?;

            // update the page
            let dst = &mut page[page_offset(addr)..page_offset(addr) + buf.len()];
            dst.copy_from_slice(buf);

            // write back
            self.map.write(page_address(addr), &page)?;
        }

        Ok(())
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

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        (*self).slice(offset)
    }
}

impl WritableAddressSpace<RVA> for &mut RelativeAddressSpace {
    fn write(&mut self, addr: RVA, buf: &[u8]) -> Result<()> {
        (*self).write(addr, buf)
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

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

impl WritableAddressSpace<VA> for AbsoluteAddressSpace {
    fn write(&mut self, addr: VA, buf: &[u8]) -> Result<()> {
        if addr < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.write((addr - self.base_address) as RVA, buf)
    }
}

impl AddressSpace<VA> for &AbsoluteAddressSpace {
    fn read_into(&self, offset: VA, buf: &mut [u8]) -> Result<()> {
        (*self).read_into(offset, buf)
    }

    fn read_ascii(&self, offset: VA, minimum_length: usize) -> Result<String> {
        (*self).read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        (*self).slice(offset)
    }
}

impl WritableAddressSpace<VA> for &mut AbsoluteAddressSpace {
    fn write(&mut self, addr: VA, buf: &[u8]) -> Result<()> {
        (*self).write(addr, buf)
    }
}

pub struct AddressSpaceSlice<'a> {
    /// offset from the start of the underlying aspace that this slice begins
    base_address: RVA,
    inner:        Box<dyn AddressSpace<u64> + 'a>,
}

impl AddressSpace<RVA> for AddressSpaceSlice<'_> {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        let offset = self.base_address + offset;
        self.inner.read_into(offset, buf)
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        let offset = self.base_address + offset;
        self.inner.read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        Ok(AddressSpaceSlice {
            base_address: offset,
            inner:        Box::new(self),
        })
    }
}

// note that slices don't support writing at the moment

impl AddressSpace<RVA> for &AddressSpaceSlice<'_> {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        (*self).read_into(offset, buf)
    }

    fn read_ascii(&self, offset: RVA, minimum_length: usize) -> Result<String> {
        (*self).read_ascii(offset, minimum_length)
    }

    fn slice(&self, offset: RVA) -> Result<AddressSpaceSlice<'_>> {
        (*self).slice(offset)
    }
}
