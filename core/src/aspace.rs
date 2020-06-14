use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};

use crate::{
    pagemap::{PageMap, PageMapError},
    RVA, VA,
};

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

    // TODO: rename read_bytes
    fn read_buf(&self, offset: T, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read a NULL-terminated, ASCII-encoded string at the given offset.
    ///
    /// Errors:
    ///
    ///   - PageMapError - if the address is not mapped.
    ///   - std::str::from_utf8 errors - if the data is not valid utf8
    ///
    fn read_ascii(&self, offset: T) -> Result<String>;
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
}

impl AddressSpace<RVA> for RelativeAddressSpace {
    fn read_into(&self, offset: RVA, buf: &mut [u8]) -> Result<()> {
        self.map.slice_into(offset, buf)?;
        Ok(())
    }

    fn read_ascii(&self, offset: RVA) -> Result<String> {
        let buf: Vec<u8> = (offset..std::u64::MAX)
            .map(|offset| self.map.get(offset))
            .take_while(|c| c.is_some())
            .map(|c| c.unwrap())
            .take_while(|&c| c != 0)
            .collect();

        Ok(String::from_utf8(buf)?)
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

impl AddressSpace<VA> for AbsoluteAddressSpace {
    fn read_into(&self, offset: VA, buf: &mut [u8]) -> Result<()> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.read_into((offset - self.base_address) as RVA, buf)
    }

    fn read_ascii(&self, offset: VA) -> Result<String> {
        if offset < self.base_address {
            return Err(PageMapError::NotMapped.into());
        }

        self.relative.read_ascii((offset - self.base_address) as RVA)
    }
}
