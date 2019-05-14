use super::arch::{Arch};

#[derive(Debug, Copy, Clone)]
pub enum XrefType {
    // mov eax, eax
    // push ebp
    Fallthrough,
    // call [0x401000]
    Call,
    // call [eax]
    //IndirectCall { src: Rva },
    // jmp 0x401000
    UnconditionalJump,
    // jmp eax
    //UnconditionalIndirectJump { src: Rva, dst: Rva },
    // jnz 0x401000
    ConditionalJump,
    // jnz eax
    //ConditionalIndirectJump { src: Rva },
    // cmov 0x1
    ConditionalMove,
}

#[derive(Debug)]
pub struct Xref<A: Arch> {
    pub src: A::RVA,
    pub dst: A::RVA,
    pub typ: XrefType,
}

// we have to implement `Clone` manually, as described in
// https://github.com/rust-lang/rust/issues/41481
// and https://github.com/rust-lang/rust/issues/26925
impl<A: Arch> Clone for Xref<A> {
    fn clone(&self) -> Self {
        Xref{
            ..*self
        }
    }
}
impl<A: Arch> Copy for Xref<A> {}
