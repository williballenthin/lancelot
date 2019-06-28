use std::fmt;
use std::hash;

use num::{FromPrimitive};



/// please don't access VA.0 directly.
/// its provided so you can construct VA like:
/// ```
/// use lancelot::arch::VA;
/// let _ = VA(0x0);
/// ```
#[derive(Copy, Clone)]
pub struct VA(pub u64);

impl VA {
    /// Compute the VA given a delta RVA, like `self:va + other:rva`.
    /// Returns None on over/underflow.
    pub fn va(&self, other: RVA) -> Option<VA> {
        if other.0 < 0 {
            Some(VA(match self.0.checked_sub((-other.0) as u64) {
                None => return None,
                Some(v) => v,
            }))
        } else {
            Some(VA(match self.0.checked_add(other.0 as u64) {
                None => return None,
                Some(v) => v,
            }))
        }
    }

    /// Compute the delta RVA from `self:va - other:va`.
    /// Returns None on over/underflow.
    pub fn rva(&self, other: VA) -> Option<RVA> {
        if other.0 > self.0 {
            let v = match other.0.checked_sub(self.0) {
                None => return None,
                Some(v) => v,
            };
            if v > std::i64::MAX as u64{
                return None;
            }
            Some(RVA(-(v as i64)))
        } else {
            let v = match self.0.checked_sub(other.0) {
                None => return None,
                Some(v) => v
            };
            if v > std::i64::MAX as u64 {
                return None;
            }
            Some(RVA(v as i64))
        }
    }
}

impl fmt::Display for VA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for VA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::LowerHex for VA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl fmt::UpperHex for VA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl hash::Hash for VA {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for VA {
    fn eq(&self, other: &VA) -> bool {
        self.0 == other.0
    }
}

impl Eq for VA {}

impl std::convert::From<usize> for VA {
    fn from(v: usize) -> VA {
        // this should only fail when we get to 128-bit architectures
        VA(v as u64)
    }
}

impl std::convert::From<u32> for VA {
    fn from(v: u32) -> VA {
        VA(v as u64)
    }
}

impl std::convert::From<u64> for VA {
    fn from(v: u64) -> VA {
        VA(v)
    }
}





/// please don't access RVA.0 directly.
/// /// its provided so you can construct RVA like:
/// ```
/// use lancelot::arch::RVA;
/// let _ = RVA(0x0);
/// ```
#[derive(Copy, Clone)]
pub struct RVA(pub i64);

impl fmt::Display for RVA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for RVA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::LowerHex for RVA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl fmt::UpperHex for RVA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl hash::Hash for RVA {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for RVA {
    fn eq(&self, other: &RVA) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for RVA {
    fn partial_cmp(&self, other: &RVA) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl Ord for RVA {
    fn cmp(&self, other: &RVA) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Eq for RVA {}

impl std::convert::From<usize> for RVA {
    /// may panic on overflow
    fn from(v: usize) -> RVA {
        RVA(i64::from_usize(v).expect("usize too large for RVA"))
    }
}

impl std::convert::Into<usize> for RVA {
    /// may panic on over/underflow
    fn into(self) -> usize {
        if self.0 < 0 {
            panic!("usize underflow")
        }
        if self.0 as u64 > std::usize::MAX as u64 {
            panic!("usize overflow");
        }
        self.0 as usize
    }
}

impl std::convert::Into<u64> for RVA {
    fn into(self) -> u64 {
        self.0 as u64
    }
}

impl std::convert::Into<i64> for RVA {
    fn into(self) -> i64 {
        self.0
    }
}

impl std::convert::From<i32> for RVA {
    fn from(v: i32) -> RVA {
        RVA(v as i64)
    }
}

impl std::convert::From<i64> for RVA {
    fn from(v: i64) -> RVA {
        RVA(v)
    }
}

impl std::ops::Add<RVA> for RVA {
    type Output = RVA;

    /// may panic on overflow
    fn add(self, rhs: RVA) -> RVA {
        RVA(self.0.checked_add(rhs.0).expect("rva overflow"))
    }
}

impl std::ops::Add<usize> for RVA {
    type Output = RVA;

    /// may panic on overflow
    fn add(self, rhs: usize) -> RVA {
        self + RVA::from(rhs)
    }
}

impl std::ops::Add<u8> for RVA {
    type Output = RVA;

    /// may panic on overflow
    fn add(self, rhs: u8) -> RVA {
        self + RVA::from(rhs as i64)
    }
}

impl std::ops::Add<i32> for RVA {
    type Output = RVA;

    /// may panic on overflow
    fn add(self, rhs: i32) -> RVA {
        self + RVA::from(rhs as i64)
    }
}



#[derive(Copy, Clone)]
pub enum Arch {
    X32,
    X64
}

impl Arch {
    pub fn get_pointer_size(&self) -> u8 {
        match self {
            Arch::X32 => 4,
            Arch::X64 => 8,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Arch::X32 => write!(f, "x32"),
            Arch::X64 => write!(f, "x64"),
        }
    }
}

impl fmt::Debug for Arch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self{
            Arch::X32 => write!(f, "x32"),
            Arch::X64 => write!(f, "x64"),
        }
    }
}

