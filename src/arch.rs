
/// Metadata that describes an architecture, such as pointer size.
///
/// see: https://stackoverflow.com/q/55785858/87207
pub trait Arch {
    /// The type used for Virtual Addresses (which are unsigned).
    type VA;

    /// The type used for Relative Virtual Addresses (signed).
    type RVA;
}

/// 32-bit Intel architecture.
pub struct Arch32;
impl Arch for Arch32{
    type VA = u32;
    type RVA = i32;
}

/// 64-bit Intel architecture.
pub struct Arch64;
impl Arch for Arch64{
    type VA = u64;
    type RVA = i64;
}
