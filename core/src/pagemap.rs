use failure::{Fail, Error};

use super::util;
use super::arch::RVA;

const PAGE_SIZE: usize = 0x1000;


#[derive(Debug, Fail)]
pub enum PageMapError {
    #[fail(display = "address not mapped")]
    NotMapped,
}

fn page(rva: RVA) -> usize {
    // depends on PAGE_SIZE
    let v: u64 = rva.into();
    // #yolo
    (v as usize) >> 12
}

fn page_offset(rva: RVA) -> usize {
    // depends on PAGE_SIZE
    let v: u64 = rva.into();
    // #yolo
    (v as usize) & 0xFFF
}

pub fn page_align(i: RVA) -> RVA {
    let v: i64 = i.into();
    RVA::from(util::align(v as usize, PAGE_SIZE))
}

struct Page<T: Default + Copy> {
    elements: [T; PAGE_SIZE],
}

impl<T: Default + Copy> Page<T> {
    fn new(items: &[T]) -> Page<T> {
        let mut page: Page<T> = Default::default();
        page.elements.copy_from_slice(items);
        page
    }
}

impl<T: Default + Copy> Default for Page<T> {
    fn default() -> Self {
        Page {
            elements: [Default::default(); PAGE_SIZE]
        }
    }
}

/// PageMap is a map-like data structure that stores `Copy` elements in pages of 0x1000.
///
/// Its a good choice when representing lots of small elements that are found at
/// contiguous indices. At the moment, indices are `RVA`.
///
/// Lookups should be quick, as they boil down to just a couple dereferences.
pub struct PageMap<T: Default + Copy> {
    pages: Vec<Option<Page<T>>>
}

impl<T: Default + Copy> PageMap<T> {
    pub fn with_capacity(capacity: RVA) -> PageMap<T>{
        let page_count = page(capacity) + 1;
        let mut pages = Vec::with_capacity(page_count);
        pages.resize_with(page_count, || None);

        PageMap {
            pages
        }
    }



    /// error if rva is not in a valid page.
    /// panic due to:
    ///   - rva must be page aligned.
    ///   - must be PAGE_SIZE number of items.
    fn map_page(&mut self, rva: RVA, items: &[T]) -> Result<(), Error> {
        if page_offset(rva) != 0 {
            panic!("invalid map address");
        }
        if items.len() != PAGE_SIZE {
            panic!("invalid map buffer size");
        }
        debug!("mapping page: {}", rva);
        if page(rva) > self.pages.len() - 1 {
            return Err(PageMapError::NotMapped.into());
        }

        self.pages[page(rva)] = Some(Page::new(items));

        Ok(())
    }

    /// map the given items at the given address.
    ///
    /// error if rva or items are not in a valid page.
    /// panic due to:
    ///   - rva must be page aligned.
    ///   - must be multiple of PAGE_SIZE number of items.
    ///
    /// see example under `get`.
    pub fn map(&mut self, rva: RVA, items: &[T]) -> Result<(), Error> {
        if items.len() % PAGE_SIZE != 0 {
            panic!("items must be page aligned");
        }
        for (i, chunk) in items.chunks_exact(PAGE_SIZE).enumerate() {
            self.map_page(rva + i * PAGE_SIZE, chunk)?;
        }
        Ok(())
    }

    /// map the default value (probably zero) at the given address for the given size.
    ///
    /// same error conditions as `map`.
    /// see example under `probe`.
    pub fn map_empty(&mut self, rva: RVA, size: usize) -> Result<(), Error> {
        self.map(rva, &vec![Default::default(); size])
    }

    /// map the given items at the given address, padding with the default value until the next page.
    /// (map zero-extend).
    ///
    /// same error conditions as `map`.
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// assert_eq!(d.get(0x0.into()), None);
    /// assert_eq!(d.get(0x1.into()), None);
    ///
    /// d.mapzx(0x0.into(), &[0x1, ]).expect("failed to map");
    /// assert_eq!(d.get(0x0.into()), Some(0x1));
    /// assert_eq!(d.get(0x1.into()), Some(0x0));
    /// ```
    pub fn mapzx(&mut self, rva: RVA, items: &[T]) -> Result<(), Error> {
        // TODO: use lancelot::util::align
        let empty_count = PAGE_SIZE - page_offset(items.len().into());
        let mut padded_items = Vec::with_capacity(items.len() + empty_count);
        padded_items.extend(items);
        padded_items.extend(&vec![Default::default(); empty_count]);
        self.map(rva, &padded_items)
    }

    /// is the given address mapped?
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// assert_eq!(d.probe(0x0.into()), false);
    /// assert_eq!(d.probe(0x1000.into()), false);
    ///
    /// d.map_empty(0x0.into(), 0x1000).expect("failed to map");
    /// assert_eq!(d.probe(0x0.into()), true);
    /// assert_eq!(d.probe(0x1000.into()), false);
    /// ```
    pub fn probe(&self, rva: RVA) -> bool {
        if page(rva) > self.pages.len() - 1 {
            return false;
        }

        return self.pages[page(rva)].is_some()
    }

    /// fetch one item from the given address.
    /// if the address is not mapped, then the result is `None`.
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// assert_eq!(d.get(0x0.into()), None);
    /// assert_eq!(d.get(0x1000.into()), None);
    ///
    /// d.map(0x1000.into(), &[0x1; 0x1000]).expect("failed to map");
    /// assert_eq!(d.get(0x0.into()), None);
    /// assert_eq!(d.get(0x1000.into()), Some(0x1));
    ///
    /// d.map(0x0.into(), &[0x2; 0x2000]).expect("failed to map");
    ///  assert_eq!(d.get(0x0.into()), Some(0x2));
    ///  assert_eq!(d.get(0x1000.into()), Some(0x2));
    /// ```
    pub fn get(&self, rva: RVA) -> Option<T> {
        if page(rva) > self.pages.len() - 1 {
            return None;
        }

        let page = match &self.pages[page(rva)] {
            // page is not mapped
            None => return None,
            // page is mapped
            Some(page) => page,
        };

        Some(page.elements[page_offset(rva)])
    }

    /// fetch one mutable item from the given address.
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// d.map_empty(0x0.into(), 0x1000).expect("failed to map");
    ///
    /// // address 0x0 starts at 0
    /// assert_eq!(d.get(0x0.into()), Some(0x0));
    ///
    /// // set address 0x0 to 1
    /// let v = d.get_mut(0x0.into()).expect("should be mapped");
    /// *v = 1;
    ///
    /// // address 0x0 is 1
    /// assert_eq!(d.get(0x0.into()), Some(0x1));
    /// ```
    pub fn get_mut(&mut self, rva: RVA) -> Option<&mut T> {
        if page(rva) > self.pages.len() - 1 {
            return None;
        }

        let page = match &mut self.pages[page(rva)] {
            // page is not mapped
            None => return None,
            // page is mapped
            Some(page) => page,
        };

        Some(&mut page.elements[page_offset(rva)])
    }


    /// handle the simple slice case: when start and end fall within the same page.
    /// for example, reading a dword from address 0x10.
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// d.map_empty(0x0.into(), 0x1000).expect("failed to map");
    /// assert_eq!(d.slice(0x0.into(), 0x2.into()).unwrap(), [0x0, 0x0]);
    /// assert_eq!(d.slice(0x1000.into(), 0x1002.into()).is_err(), true);
    /// ```
    fn slice_into_simple<'a>(&self, start: RVA, buf: &'a mut [T]) -> Result<&'a [T], Error> {
        // precondition: page(start) == page(start + buf.len())

        if page(start) > self.pages.len() - 1 {
            return Err(PageMapError::NotMapped.into());
        }

        let page = match &self.pages[page(start)] {
            // page is not mapped
            None => return Err(PageMapError::NotMapped.into()),
            // page is mapped
            Some(page) => page,
        };

        let end = start + buf.len();
        let elements = &page.elements[page_offset(start)..page_offset(end)];
        buf.copy_from_slice(elements);

        Ok(buf)
    }

    /// handle the complex slice case: when start and end are on different pages.
    /// for example, reading a dword from address 0xFFE.
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x5000.into());
    /// d.map_empty(0x1000.into(), 0x3000).expect("failed to map");
    ///
    /// // 0     unmapped
    /// //       unmapped
    /// // 1000  0 0 0 0
    /// //       0 0 0 0
    /// // 2000  0 0 0 0
    /// //       0 0 0 0
    /// // 3000  0 0 0 0
    /// //       0 0 0 0
    /// // 4000  unmapped
    /// //       unmapped
    /// // 5000  unmapped
    ///
    /// assert_eq!(d.slice(0x1FFC.into(), 0x2000.into()).unwrap(), [0x0, 0x0, 0x0, 0x0], "no overlap");
    /// assert_eq!(d.slice(0x1FFD.into(), 0x2001.into()).unwrap(), [0x0, 0x0, 0x0, 0x0], "overlap 1");
    /// assert_eq!(d.slice(0x1FFE.into(), 0x2002.into()).unwrap(), [0x0, 0x0, 0x0, 0x0], "overlap 2");
    /// assert_eq!(d.slice(0x1FFF.into(), 0x2003.into()).unwrap(), [0x0, 0x0, 0x0, 0x0], "overlap 3");
    /// assert_eq!(d.slice(0x2000.into(), 0x2004.into()).unwrap(), [0x0, 0x0, 0x0, 0x0], "overlap 4");
    ///
    /// assert_eq!(d.slice(0x1FFC.into(), 0x3004.into()).unwrap().len(), 0x1008, "4, page, 4");
    ///
    /// assert_eq!(d.slice(0x1FFC.into(), 0x3000.into()).unwrap().len(), 0x1004, "4, page");
    ///
    /// assert_eq!(d.slice(0x2000.into(), 0x3004.into()).unwrap().len(), 0x1004, "page, 4");
    /// ```
    fn slice_into_split<'a>(&self, start: RVA, buf: &'a mut [T]) -> Result<&'a [T], Error> {
        let end = start + buf.len();
        let start_page = page(start);
        let end_page = if page_offset(end) == 0 { page(end) - 1} else { page(end) };

        if end_page > self.pages.len() - 1 {
            return Err(PageMapError::NotMapped.into());
        }

        // ensure each page within the requested region is mapped.
        for page in start_page..end_page + 1 {
            if ! self.probe((page * PAGE_SIZE).into()) {
                return Err(PageMapError::NotMapped.into());
            }
        }

        let mut offset: usize = 0;

        // region one: from `start` to the end of its page
        // region two: any intermediate complete pages
        // region three: from start of final page until `end`

        // one.
        {
            let page = self.pages[page(start)].as_ref().expect("slice_into_split: one");
            let elements = &page.elements[page_offset(start)..];
            {
                let dst = &mut buf[offset..offset+elements.len()];
                dst.copy_from_slice(elements);
                offset += elements.len();
            }
        }

        // two.
        if page(start) != page(end) - 1 {
            let start_index = page(start) + 1;
            let end_index = page(end);
            for page_index in start_index..end_index {
                let page = self.pages[page_index].as_ref().expect("slice_into_split: two");
                let elements = &page.elements[..];
                {
                    let dst = &mut buf[offset..offset+elements.len()];
                    dst.copy_from_slice(elements);
                    offset += elements.len();
                }
            }
        }

        // three.
        if page_offset(end) != 0x0 {
            let page = self.pages[page(end)].as_ref().expect("slice_into_split: three");
            let elements = &page.elements[..page_offset(end)];
            {
                let dst = &mut buf[offset..offset+elements.len()];
                dst.copy_from_slice(elements);
            }
        }

        Ok(buf)
    }

    /// fetch the items found in the given range, placing them into the given slice.
    /// compared with `slice`, this routine avoids an allocation.
    ///
    /// errors:
    ///   - PageMapError::NotMapped: if any requested address is not mapped
    pub fn slice_into<'a>(&self, start: RVA, buf: &'a mut [T]) -> Result<&'a [T], Error> {
        let end = start + buf.len();
        if page(start) == page(end) {
            self.slice_into_simple(start, buf)
        } else {
            self.slice_into_split(start, buf)
        }
    }

    /// fetch the items found in the given range.
    ///
    /// errors:
    ///   - PageMapError::NotMapped: if any requested address is not mapped
    ///
    /// panic if:
    ///   - start > end
    ///
    /// ```
    /// use lancelot::arch::RVA;
    /// use lancelot::pagemap::PageMap;
    ///
    /// let mut d: PageMap<u32> = PageMap::with_capacity(0x2000.into());
    /// d.map_empty(0x0.into(), 0x1000).expect("failed to map");
    ///
    /// assert_eq!(d.slice(0x0.into(), 0x2.into()).unwrap(), [0x0, 0x0]);
    /// assert!(d.slice(0x0.into(), 0x1000.into()).is_ok(), "read page");
    /// assert!(d.slice(0x0.into(), 0x1001.into()).is_err(), "read more than a page");
    /// ```
    pub fn slice(&self, start: RVA, end: RVA) -> Result<Vec<T>, Error> {
        if start > end {
            panic!("start > end");
        }

        let mut ret = vec![Default::default(); (end - start).into()];
        self.slice_into(start, &mut ret)?;

        Ok(ret)
    }
}
