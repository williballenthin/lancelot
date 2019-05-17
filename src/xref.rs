use super::arch::Arch;

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
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
        Xref { ..*self }
    }
}
impl<A: Arch> Copy for Xref<A> {}

impl<A: Arch> std::fmt::Display for Xref<A>{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "xref(type: {:?}, src: {:#x}, dst: {:#x})", self.typ, self.src, self.dst)
    }
}

impl<A: Arch> std::fmt::Debug for Xref<A>{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // just use the `Display` impl for now
        write!(f, "{}", self)
    }
}

impl<A: Arch> PartialEq for Xref<A> {
    fn eq(&self, other: &Xref<A>) -> bool {
        self.src == other.src &&
            self.dst == other.dst &&
            self.typ == other.typ
    }
}
impl<A: Arch> Eq for Xref<A> {}

impl<A: Arch> std::hash::Hash for Xref<A> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src.hash(state);
        self.dst.hash(state);
        self.typ.hash(state);
    }
}
