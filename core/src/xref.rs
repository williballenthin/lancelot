use super::arch::RVA;

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

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Xref {
    pub src: RVA,
    pub dst: RVA,
    pub typ: XrefType,
}
