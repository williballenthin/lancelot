use std::collections::BTreeMap;

use anyhow::Result;
use bitflags::*;
use bitvec::{prelude::*, vec::BitVec};
use thiserror::Error;

use crate::{module::Permissions, VA};

const PAGE_SIZE: usize = 0x1000;
const PAGE_SHIFT: usize = 12;
const PAGE_MASK: u64 = 0xFFF;
type PageFrame = [u8; PAGE_SIZE];
const EMPTY_PAGE: PageFrame = [0u8; PAGE_SIZE];

/// Page Frame Number
/// "4 billion pages ought to be enough for everyone!"
/// u32 <= usize for all 32- and 64-bit systems,
/// so you'll some casting to/from usize.
type PFN = u32;

/// A collection of "physical" pages of memory, indexed by `PFN`.
#[derive(Clone)]
struct PageFrames {
    // page frames indexed by `PFN`.
    frames:            Vec<PageFrame>,
    // allocation status, indexed by `PFN`.
    // when `true`, the page is allocated.
    allocation_bitmap: BitVec,
}

impl Default for PageFrames {
    fn default() -> Self {
        PageFrames {
            frames:            vec![],
            allocation_bitmap: bitvec!(),
        }
    }
}

impl PageFrames {
    /// suggest that `page_count` pages will be allocated soon.
    /// useful to avoid frequent reallocations.
    fn reserve(&mut self, page_count: u32) {
        self.frames.reserve(page_count as usize);
        self.allocation_bitmap.reserve(page_count as usize);
    }

    /// allocate a new page frame, returning the PFN.
    /// page frame contents will be empty.
    fn allocate(&mut self) -> PFN {
        let maybe_free_index = self
            .allocation_bitmap
            .iter()
            .enumerate()
            .find(|(_, b)| !**b)
            .map(|(i, _)| i);

        if let Some(pfn) = maybe_free_index {
            self.allocation_bitmap.set(pfn, true);
            pfn as PFN
        } else {
            self.frames.push(EMPTY_PAGE);
            self.allocation_bitmap.push(true);
            (self.frames.len() - 1) as PFN
        }
    }

    /// deallocate a page by its PFN.
    /// panics if the page is not allocated.
    fn deallocate(&mut self, pfn: PFN) {
        assert!(self.allocation_bitmap.get(pfn as usize).unwrap());

        // zero pages upon deallocation.
        self.frames[pfn as usize] = EMPTY_PAGE;
        self.allocation_bitmap.set(pfn as usize, false);
    }
}

impl std::ops::Index<PFN> for PageFrames {
    type Output = PageFrame;

    fn index(&self, index: PFN) -> &PageFrame {
        &self.frames[index as usize]
    }
}

impl std::ops::IndexMut<PFN> for PageFrames {
    fn index_mut(&mut self, index: PFN) -> &mut PageFrame {
        &mut self.frames[index as usize]
    }
}

bitflags! {
    pub struct PageFlags: u32 {
        /// matches [crate::module::Permissions]
        const PERM_R = 0b00000001;
        const PERM_W = 0b00000010;
        const PERM_X = 0b00000100;
        const PERM_RW = Self::PERM_R.bits | Self::PERM_W.bits;
        const PERM_RX =  Self::PERM_R.bits | Self::PERM_X.bits;
        const PERM_WX =  Self::PERM_W.bits | Self::PERM_X.bits;
        const PERM_RWX =  Self::PERM_R.bits | Self::PERM_W.bits | Self::PERM_X.bits;

        /// a zero page, not backed by a Page Frame.
        /// upon write, allocate Page Frame on demand.
        const ZERO = 0b00001000;

        /// upon write, allocate Page Frame, copy frame, update mapping, and do the write.
        const COW = 0b00010000;
    }
}

#[derive(Error, Debug)]
pub enum MMUError {
    #[error("address already mapped: {0:#x}")]
    AddressAlreadyMapped(VA),
    #[error("address not mapped: {0:#x}")]
    AddressNotMapped(VA),
    #[error("address not readable: {0:#x}")]
    AddressNotReadable(VA),
    #[error("address not writable: {0:#x}")]
    AddressNotWritable(VA),
}

#[derive(Default, Clone)]
pub struct MMU {
    pages:   PageFrames,
    mapping: BTreeMap<VA, (PFN, PageFlags)>,
}

fn is_page_aligned(va: VA) -> bool {
    va & PAGE_MASK == 0x0
}

fn page_number(va: VA) -> u64 {
    (va >> PAGE_SHIFT) << PAGE_SHIFT
}

fn page_offset(va: VA) -> usize {
    (va & PAGE_MASK) as usize
}

impl MMU {
    // map memory at the given virtual address, for the given size, with the given
    // perms. panics if `addr` or `size` are not page aligned.
    pub fn mmap(&mut self, addr: VA, size: u64, perms: Permissions) -> Result<()> {
        assert!(is_page_aligned(addr));
        assert!(is_page_aligned(size));

        let page_count = size / PAGE_SIZE as u64;
        assert!(page_count <= u32::MAX as u64);

        // ensure none of the pages are already mapped.
        // Linux mmap updates any existing mappings.
        // I'm not sure if we'd prefer to go that route or not.
        // being conservative here will help us find bugs early on.
        //
        // do this all at once up front to avoid getting
        // half way through and needing to bail.
        for i in 0..page_count {
            let page_va = addr + i * PAGE_SIZE as u64;
            if self.mapping.contains_key(&page_va) {
                return Err(MMUError::AddressAlreadyMapped(page_va).into());
            }
        }

        self.pages.reserve(page_count as u32);

        let flags = PageFlags::ZERO | PageFlags::from_bits_truncate(perms.bits() as u32);
        for i in 0..page_count {
            let page_va = addr + i * PAGE_SIZE as u64;

            // initially, don't allocate any page frames, just use zero pages.
            // only when written to should we allocate page on demand.
            // this should be just as fast, since we've reserved the pages above.
            self.mapping.insert(page_va, (u32::MAX, flags));
        }

        Ok(())
    }

    fn probe_read(&self, addr: VA) -> Result<(PFN, PageFlags)> {
        let (pfn, flags) = match self.mapping.get(&page_number(addr)) {
            Some(&(pfn, flags)) => (pfn, flags),
            None => return Err(MMUError::AddressNotMapped(addr).into()),
        };

        if !flags.intersects(PageFlags::PERM_R) {
            return Err(MMUError::AddressNotReadable(addr).into());
        }

        Ok((pfn, flags))
    }

    pub fn read_u8(&self, addr: VA) -> Result<u8> {
        let (pfn, flags) = self.probe_read(addr)?;

        if flags.intersects(PageFlags::ZERO) {
            return Ok(0);
        }

        let pf = self.pages[pfn];
        Ok(pf[page_offset(addr)])
    }

    pub fn write_u8(&mut self, addr: VA, value: u8) -> Result<()> {
        let (pfn, flags) = match self.mapping.get(&page_number(addr)) {
            Some(&(pfn, flags)) => (pfn, flags),
            None => return Err(MMUError::AddressNotMapped(addr).into()),
        };

        if !flags.intersects(PageFlags::PERM_W) {
            return Err(MMUError::AddressNotWritable(addr).into());
        }

        let pfn = if flags.intersects(PageFlags::ZERO) || flags.intersects(PageFlags::COW) {
            // collect a copy of the existing page frame contents
            let pf = if flags.intersects(PageFlags::ZERO) {
                EMPTY_PAGE
            } else {
                self.pages[pfn].clone()
            };

            // and write it into a newly allocated page frame
            let pfn = self.pages.allocate();
            *(&mut self.pages[pfn]) = pf;

            // now update the mapping to point to the new pf
            let mut flags = flags;
            flags.remove(PageFlags::ZERO);
            flags.remove(PageFlags::COW);

            self.mapping.insert(page_number(addr), (pfn, flags));
            pfn
        } else {
            pfn
        };

        (&mut self.pages[pfn])[page_offset(addr)] = value;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    mod pf {
        use crate::emu::mmu::*;
        use anyhow::Result;

        #[test]
        fn allocate() -> Result<()> {
            let mut pfs: PageFrames = Default::default();

            assert_eq!(pfs.allocate(), 0);
            assert_eq!(pfs.allocate(), 1);

            Ok(())
        }

        #[test]
        fn deallocate() -> Result<()> {
            let mut pfs: PageFrames = Default::default();

            assert_eq!(pfs.allocate(), 0);
            pfs.deallocate(0);
            assert_eq!(pfs.allocate(), 0);
            assert_eq!(pfs.allocate(), 1);
            pfs.deallocate(0);
            assert_eq!(pfs.allocate(), 0);

            Ok(())
        }

        #[test]
        fn reserve() -> Result<()> {
            let mut pfs: PageFrames = Default::default();
            pfs.reserve(1);

            // no change in behavior
            assert_eq!(pfs.allocate(), 0);
            pfs.deallocate(0);
            assert_eq!(pfs.allocate(), 0);

            Ok(())
        }

        #[test]
        fn index() -> Result<()> {
            let mut pfs: PageFrames = Default::default();

            assert_eq!(pfs.allocate(), 0);
            assert_eq!(pfs[0], EMPTY_PAGE);

            {
                let pf = &mut pfs[0];
                pf[0] = 0xFF;
            }

            assert_ne!(pfs[0], EMPTY_PAGE);

            Ok(())
        }
    }

    #[cfg(test)]
    mod mmu {
        use crate::emu::mmu::*;
        use anyhow::Result;

        #[test]
        fn access_violation() -> Result<()> {
            let mmu: MMU = Default::default();

            assert!(mmu.read_u8(0x0).is_err());
            assert!(mmu.read_u8(0x1).is_err());

            Ok(())
        }

        #[test]
        fn mmap() -> Result<()> {
            let mut mmu: MMU = Default::default();

            assert!(mmu.read_u8(0x1000).is_err());

            mmu.mmap(0x1000, 0x2000, Permissions::R).unwrap();

            assert!(mmu.read_u8(0xFFF).is_err());
            assert_eq!(mmu.read_u8(0x1000).unwrap(), 0x0);
            assert_eq!(mmu.read_u8(0x2000).unwrap(), 0x0);
            assert!(mmu.read_u8(0x3000).is_err());

            Ok(())
        }

        #[test]
        fn write_u8() -> Result<()> {
            let mut mmu: MMU = Default::default();

            assert!(mmu.write_u8(0x1000, 1).is_err());

            mmu.mmap(0x1000, 0x1000, Permissions::R).unwrap();
            mmu.mmap(0x2000, 0x1000, Permissions::RW).unwrap();

            assert!(mmu.write_u8(0x1000, 1).is_err());
            assert_eq!(mmu.read_u8(0x1000).unwrap(), 0);

            assert!(mmu.write_u8(0x2000, 1).is_ok());
            assert_eq!(mmu.read_u8(0x2000).unwrap(), 1);

            Ok(())
        }
    }
}
