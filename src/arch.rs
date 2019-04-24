use std::fmt;
use num::{Zero};
use std::ops::Add;

extern crate num;
use num::FromPrimitive;
use num::CheckedAdd;

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
    type VA:
        // trait Ord so that we can compare addresses.
        Ord
        // trait Add so that we can do VA + RVA -> VA
        //  technically, we should constrain Add to Add<RHS=RVA>
        //  but, signed + unsigned addition is not implemented.
        //  atm, we push this down to the user.
        //  TODO: provide helper routines to make this easy.
        + Add<Output=Self::VA>
        + Zero
        // trait Copy because this is just a number, so prefer copy semantics.
        + Copy
        ;

    /// The type used for Relative Virtual Addresses (signed).
    type RVA:
        // trait Ord so that we can compare offsets.
        Ord
        + Zero
        // trait Add so that we can do VA + RVA -> VA.
        //  see note above.
        + Add<Output=Self::RVA>
        // trait Add so that we can do RVA + RVA -> RVA.
        + Add<Self::RVA, Output=Self::RVA>
        + CheckedAdd<Output=Self::RVA>
        // trait FromPrimitive so that we can convert from usize (vec length) to offset.
        + FromPrimitive
        // trait Copy because this is just a number, so prefer copy semantics.
        + Copy
        ;
}

/// 32-bit Intel architecture.
pub struct Arch32;
impl Arch for Arch32 {
    type VA = u32;
    type RVA = i32;
}


impl fmt::Display for Arch32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x32")
    }
}

/// 64-bit Intel architecture.
pub struct Arch64;
impl Arch for Arch64 {
    type VA = u64;
    type RVA = i64;
}

impl fmt::Display for Arch64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "x64")
    }
}


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
/// assert_eq!(true, rva_plus_usize::<Arch32>(0x0, 0x1).is_some());
/// assert_eq!(0x1, rva_plus_usize::<Arch32>(0x0, 0x1).unwrap());
///
/// // returns None if the operation wraps.
/// assert_eq!(true, rva_plus_usize::<Arch32>(0x0, 0xFFFFFFFF).is_none());
/// ```
pub fn rva_plus_usize<A: Arch>(base: A::RVA, offset: usize) -> Option<A::RVA> {
    if let Some(v) = A::RVA::from_usize(offset) {
        base.checked_add(&v)
    } else {
        None
    }
}
