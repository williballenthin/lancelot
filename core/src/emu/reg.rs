// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture

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

// cf - result of an arithmetic operation on unsigned numbers is out of range.
// of - out-of-range result on signed numbers.
// sf - sign of the result. Simply a copy of the most significant bit of the
// result. af - operation produced a carry or borrow in the
// low-order 4 bits (nibble) of 8-, 16-, or 32-bit operands.
//      No conditional jump instructions with this flag.
// pf - Indicates even parity of the low 8 bits of the result.
//      PF is set if the lower 8 bits contain even number 1 bits.
// zf - result is zero.
// http://service.scs.carleton.ca/sivarama/asm_book_web/Student_copies/ch6_arithmetic.pdf

const FLAG_CF: u8 = 0;
const FLAG_PF: u8 = 2;
const FLAG_AF: u8 = 4;
const FLAG_ZF: u8 = 6;
const FLAG_SF: u8 = 7;
const FLAG_DF: u8 = 10;
const FLAG_OF: u8 = 11;

pub const STATUS_MASK: u64 = (1 << FLAG_CF)
    | (1 << FLAG_PF)
    | (1 << FLAG_AF)
    | (1 << FLAG_ZF)
    | (1 << FLAG_SF)
    | (1 << FLAG_DF)
    | (1 << FLAG_OF);

macro_rules! flag {
    ($index:ident, $get:ident, $set:ident) => {
        #[inline]
        pub fn $get(&self) -> bool {
            (self.rflags & (1 << $index)) > 0
        }

        #[inline]
        pub fn $set(&mut self, is_set: bool) {
            if is_set {
                self.rflags |= 1 << $index;
            } else {
                self.rflags &= !(1 << $index);
            }
        }
    };
}

macro_rules! reg {
    ($reg:ident, $get_64:ident, $get_32:ident, $get_16:ident, $get_8l:ident, $set_64:ident, $set_32:ident, $set_16:ident, $set_8l:ident) => {
        #[inline]
        pub fn $get_64(&self) -> u64 {
            self.$reg
        }

        #[inline]
        pub fn $get_32(&self) -> u32 {
            (self.$reg & 0xFFFF_FFFF) as u32
        }

        #[inline]
        pub fn $get_16(&self) -> u16 {
            (self.$reg & 0xFFFF) as u16
        }

        #[inline]
        pub fn $get_8l(&self) -> u8 {
            (self.$reg & 0xFF) as u8
        }

        #[inline]
        pub fn $set_64(&mut self, value: u64) {
            self.$reg = value;
        }

        #[inline]
        pub fn $set_32(&mut self, value: u32) {
            self.$reg = value as u64;
        }

        #[inline]
        pub fn $set_16(&mut self, value: u16) {
            // only lower 16-bits of a register can be set
            // without overwriting higher parts.
            // https://stackoverflow.com/questions/48449833/move-smaller-operand-into-larger-operand#comment83894774_48450559
            self.$reg &= 0xFFFF_FFFF_FFFF_0000;
            self.$reg |= (value as u64) & 0xFFFF;
        }

        #[inline]
        pub fn $set_8l(&mut self, value: u8) {
            self.$reg &= 0xFFFF_FFFF_FFFF_FF00;
            self.$reg |= (value as u64) & 0xFF;
        }
    };
}

// generate accessor and mutator for the "h" register flavor.
// that is, the 2nd least significant byte, such as AH.
macro_rules! regh {
    ($reg:ident, $get_8h:ident, $set_8h:ident) => {
        #[inline]
        pub fn $get_8h(&self) -> u8 {
            ((self.$reg & 0xFF00) >> 8) as u8
        }

        #[inline]
        pub fn $set_8h(&mut self, value: u8) {
            self.$reg &= 0xFFFF_FFFF_FFFF_00FF;
            self.$reg |= ((value as u64) & 0xFF) << 8;
        }
    };
}

impl Registers {
    reg!(rax, rax, eax, ax, al, set_rax, set_eax, set_ax, set_al);

    regh!(rax, ah, set_ah);

    reg!(rbx, rbx, ebx, bx, bl, set_rbx, set_ebx, set_bx, set_bl);

    regh!(rbx, bh, set_bh);

    reg!(rcx, rcx, ecx, cx, cl, set_rcx, set_ecx, set_cx, set_cl);

    regh!(rcx, ch, set_ch);

    reg!(rdx, rdx, edx, dx, dl, set_rdx, set_edx, set_dx, set_dl);

    regh!(rdx, dh, set_dh);

    reg!(r8, r8, r8d, r8w, r8b, set_r8, set_r8d, set_r8w, set_r8b);

    reg!(r9, r9, r9d, r9w, r9b, set_r9, set_r9d, set_r9w, set_r9b);

    reg!(r10, r10, r10d, r10w, r10b, set_r10, set_r10d, set_r10w, set_r10b);

    reg!(r11, r11, r11d, r11w, r11b, set_r11, set_r11d, set_r11w, set_r11b);

    reg!(r12, r12, r12d, r12w, r12b, set_r12, set_r12d, set_r12w, set_r12b);

    reg!(r13, r13, r13d, r13w, r13b, set_r13, set_r13d, set_r13w, set_r13b);

    reg!(r14, r14, r14d, r14w, r14b, set_r14, set_r14d, set_r14w, set_r14b);

    reg!(r15, r15, r15d, r15w, r15b, set_r15, set_r15d, set_r15w, set_r15b);

    reg!(rsi, rsi, esi, si, sil, set_rsi, set_esi, set_si, set_sil);

    reg!(rdi, rdi, edi, di, dil, set_rdi, set_edi, set_di, set_dil);

    reg!(rsp, rsp, esp, sp, spl, set_rsp, set_esp, set_sp, set_spl);

    reg!(rbp, rbp, ebp, bp, bpl, set_rbp, set_ebp, set_bp, set_bpl);

    // register IPL is made up, please don't use.
    reg!(rip, rip, eip, ip, _ipl_fake, set_rip, set_eip, set_ip, _set_ipl);

    flag!(FLAG_CF, cf, set_cf);

    flag!(FLAG_PF, pf, set_pf);

    flag!(FLAG_AF, af, set_af);

    flag!(FLAG_ZF, zf, set_zf);

    flag!(FLAG_SF, sf, set_sf);

    flag!(FLAG_DF, df, set_df);

    flag!(FLAG_OF, of, set_of);

    pub fn es(&self) -> u16 {
        self.es
    }

    pub fn cs(&self) -> u16 {
        self.cs
    }

    pub fn ss(&self) -> u16 {
        self.ss
    }

    pub fn ds(&self) -> u16 {
        self.ds
    }

    pub fn fs(&self) -> u16 {
        self.fs
    }

    pub fn gs(&self) -> u16 {
        self.gs
    }

    // flags
    // https://www.cs.utexas.edu/~byoung/cs429/condition-codes.pdf

    #[inline]
    pub fn rflags(&self) -> u64 {
        self.rflags
    }
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
