#[derive(Default, Clone)]
pub struct Registers {
    pub rax:    u64,
    pub rbx:    u64,
    pub rcx:    u64,
    pub rdx:    u64,
    pub rsp:    u64,
    pub rbp:    u64,
    pub rsi:    u64,
    pub rdi:    u64,
    pub r8:     u64,
    pub r9:     u64,
    pub r10:    u64,
    pub r11:    u64,
    pub r12:    u64,
    pub r13:    u64,
    pub r14:    u64,
    pub r15:    u64,
    pub rflags: u64,
    pub rip:    u64,
    pub es:     u16,
    pub cs:     u16,
    pub ss:     u16,
    pub ds:     u16,
    pub fs:     u16,
    pub gs:     u16,
    pub gdtr:   u64,
    pub ldtr:   u64,
    pub idtr:   u64,
    pub fpu:    Option<Box<FPU>>,
    pub avx:    Option<Box<AVX>>,
}

impl Registers {
    // TODO: inline this?

    pub fn rax(&self) -> u64 {
        self.rax
    }

    pub fn eax(&self) -> u64 {
        self.rax & 0xFFFF_FFFF
    }

    pub fn ax(&self) -> u64 {
        self.rax & 0xFFFF
    }

    pub fn ah(&self) -> u64 {
        (self.rax & 0xFF00) >> 8
    }

    pub fn al(&self) -> u64 {
        self.rax & 0xFF
    }

    // TODO: macro to generate these accessors
    // reg!(rax, eax, ax, ah, al)
}

#[derive(Default, Clone)]
pub struct FPU {
    // TODO: this is not thought out at all.
    pub st0:        f64,
    pub st1:        f64,
    pub st2:        f64,
    pub st3:        f64,
    pub st4:        f64,
    pub st5:        f64,
    pub st6:        f64,
    pub st7:        f64,
    pub x87control: u64,
    pub x87status:  u64,
    pub x87tag:     u64,
}

#[derive(Default, Clone)]
pub struct AVX {
    pub zmm0:  [u8; 32],
    pub zmm1:  [u8; 32],
    pub zmm2:  [u8; 32],
    pub zmm3:  [u8; 32],
    pub zmm4:  [u8; 32],
    pub zmm5:  [u8; 32],
    pub zmm6:  [u8; 32],
    pub zmm7:  [u8; 32],
    pub zmm8:  [u8; 32],
    pub zmm9:  [u8; 32],
    pub zmm10: [u8; 32],
    pub zmm11: [u8; 32],
    pub zmm12: [u8; 32],
    pub zmm13: [u8; 32],
    pub zmm14: [u8; 32],
    pub zmm15: [u8; 32],
    pub zmm16: [u8; 32],
    pub zmm17: [u8; 32],
    pub zmm18: [u8; 32],
    pub zmm19: [u8; 32],
    pub zmm20: [u8; 32],
    pub zmm21: [u8; 32],
    pub zmm22: [u8; 32],
    pub zmm23: [u8; 32],
    pub zmm24: [u8; 32],
    pub zmm25: [u8; 32],
    pub zmm26: [u8; 32],
    pub zmm27: [u8; 32],
    pub zmm28: [u8; 32],
    pub zmm29: [u8; 32],
    pub zmm30: [u8; 32],
    pub zmm31: [u8; 32],
}
