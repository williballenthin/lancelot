#[derive(Copy, Clone, Debug)]
pub enum Arch {
    X32,
    X64,
}

impl Arch {
    pub fn pointer_size(&self) -> usize {
        match self {
            Arch::X32 => 4,
            Arch::X64 => 8,
        }
    }
}
