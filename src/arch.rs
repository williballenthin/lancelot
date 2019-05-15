use num::Zero;
use std::fmt;
use std::fmt::Debug;
use std::hash;
use std::hash::Hash;
use std::ops::{Add, Sub};

extern crate num;
use num::{CheckedAdd, CheckedSub, FromPrimitive, ToPrimitive};

/// Type infrastructure that describes an architecture,
///  with details such as pointer size.
///
/// Useful for specifying the appropriate member types for pointers, etc.
/// That is, when a struct contains an RVA, its 32-bits or 64-bits depending on Arch.
///
/// Example:
///
/// ```
/// use lancelot::arch::{Arch, Arch32};
///
/// struct Section<A: Arch> {
///   addr: A::RVA,
///   buf:  Vec<u8>,
///   name: String,
/// }
///
/// let s: Section::<Arch32> = Section {
///   addr: 0x0,
///   buf: vec![],
///   name: "foo".to_string(),
/// };
/// ```
///
/// see: https://stackoverflow.com/q/55785858/87207
pub trait Arch {
    /// The type used for Virtual Addresses (which are unsigned).
    type VA: Ord + Add<Output = Self::VA> + Zero + FromPrimitive + ToPrimitive + Copy + Debug;

    /// The type used for Relative Virtual Addresses (signed).
    type RVA: Ord
        + Zero
        + Hash
        + fmt::LowerHex
        + Add<Output = Self::RVA>
        + Sub<Output = Self::RVA>
        + Add<Self::RVA, Output = Self::RVA>
        + CheckedAdd<Output = Self::RVA>
        + CheckedSub<Output = Self::RVA>
        + FromPrimitive
        + ToPrimitive
        + Copy
        + Debug;

    fn get_bits() -> u8;
}

/// 32-bit Intel architecture.
pub struct Arch32;
impl Arch for Arch32 {
    type VA = u32;
    type RVA = i32;
    fn get_bits() -> u8 {
        32
    }
}

impl fmt::Display for Arch32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x32")
    }
}

impl fmt::Debug for Arch32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x32")
    }
}

impl hash::Hash for Arch32 {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "x32".hash(state);
    }
}

impl PartialEq for Arch32 {
    fn eq(&self, _other: &Arch32) -> bool {
        true
    }
}

impl Eq for Arch32 {}

/// 64-bit Intel architecture.
pub struct Arch64;
impl Arch for Arch64 {
    type VA = u64;
    type RVA = i64;
    fn get_bits() -> u8 {
        64
    }
}

impl fmt::Display for Arch64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x64")
    }
}

impl fmt::Debug for Arch64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x64")
    }
}

impl hash::Hash for Arch64 {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "x64".hash(state);
    }
}

impl PartialEq for Arch64 {
    fn eq(&self, other: &Arch64) -> bool {
        true
    }
}

impl Eq for Arch64 {}

/// Checked arithmetic across RVA and usize.
///
/// We'd like RVA to be trait `Add<usize, Output=RVA>`.
/// However, this cannot be the case when `<RVA=u32>`
///  as we then have `i32 + u32` which can overflow `i32`.
/// So, we have to do checked arithmetic.
///
/// Example:
///
/// ```
/// use lancelot::arch::*;
///
/// // returns Some if the operation does not wrap:
/// assert_eq!(true, rva_add_usize::<Arch32>(0x0, 0x1).is_some());
/// assert_eq!(0x1,  rva_add_usize::<Arch32>(0x0, 0x1).unwrap());
///
/// // returns None if the operation wraps.
/// assert_eq!(true, rva_add_usize::<Arch32>(0x0, 0xFFFFFFFF).is_none());
/// ```
pub fn rva_add_usize<A: Arch>(base: A::RVA, offset: usize) -> Option<A::RVA> {
    if let Some(v) = A::RVA::from_usize(offset) {
        base.checked_add(&v)
    } else {
        None
    }
}

/// Checked arithmetic across RVA and usize.
///
/// We'd like RVA to be trait `Sub<usize, Output=RVA>`.
/// However, this cannot be the case when `<RVA=u32>`
///  as we then have `i32 - u32` which can underflow `i32`.
/// So, we have to do checked arithmetic.
///
/// Example:
///
/// ```
/// use std::i32;
/// use lancelot::arch::*;
///
/// // returns Some if the operation does not wrap:
/// assert_eq!(true, rva_sub_usize::<Arch32>(0x1, 0x0).is_some());
/// assert_eq!(0x1,  rva_sub_usize::<Arch32>(0x1, 0x0).unwrap());
///
/// // returns None if the operation wraps.
/// assert_eq!(true, rva_sub_usize::<Arch32>(std::i32::MAX, 0xFFFFFFFF).is_none());
/// ```
pub fn rva_sub_usize<A: Arch>(base: A::RVA, offset: usize) -> Option<A::RVA> {
    if let Some(v) = A::RVA::from_usize(offset) {
        base.checked_sub(&v)
    } else {
        None
    }
}

pub fn va_compute_rva<A: Arch>(base: A::VA, va: A::VA) -> Option<A::RVA> {
    if va < base {
        None
    } else {
        let base = A::VA::to_u64(&base).unwrap();
        let va = A::VA::to_u64(&va).unwrap();
        let rva = va - base;
        A::RVA::from_u64(rva)
    }
}
