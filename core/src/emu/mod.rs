#![allow(clippy::nonstandard_macro_braces)] // clippy bug, see https://github.com/rust-lang/rust-clippy/issues/7434

use std::unimplemented;

use anyhow::Result;
use log::debug;
use thiserror::Error;
use zydis::{enums::Register, DecodedInstruction, DecodedOperand};

use crate::{
    arch::Arch,
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};

pub mod mmu;
pub mod plat;
pub mod reg;

#[derive(Error, Debug)]
pub enum EmuError {
    #[error("invalid instruction: {0:#x}")]
    InvalidInstruction(VA),
    #[error("callback errored: {0:#?}")]
    CallbackError(anyhow::Error),
}

#[derive(Error, Debug)]
pub enum FetchError {
    #[error("invalid instruction: {0:#x}")]
    InvalidInstruction(VA),

    #[error("fetch: not mapped: at {va:#x}")]
    AddressNotMapped {
        va:     VA,
        #[source]
        source: mmu::MMUError, /* ::AddressNotMapped */
    },

    #[error("fetch: access violation: at {va:#x}")]
    AccessViolation {
        va:     VA,
        #[source]
        source: mmu::MMUError, /* ::AccessViolation */
    },
}

#[derive(Error, Debug)]
pub enum WriteError {
    #[error("write: not mapped: {size:#x} bytes at {va:#x}")]
    AddressNotMapped {
        va:     VA,
        size:   u16,
        #[source]
        source: mmu::MMUError, /* ::AddressNotMapped */
    },

    #[error("write: access violation: {size:#x} bytes at {va:#x}")]
    AccessViolation {
        va:     VA,
        size:   u16,
        #[source]
        source: mmu::MMUError, /* ::AccessViolation */
    },
}

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("read: not mapped: {size:#x} bytes at {va:#x}")]
    AddressNotMapped {
        va:     VA,
        size:   u16,
        #[source]
        source: mmu::MMUError, /* ::AddressNotMapped */
    },

    #[error("read: access violation: {size:#x} bytes at {va:#x}")]
    AccessViolation {
        va:     VA,
        size:   u16,
        #[source]
        source: mmu::MMUError, /* ::AccessViolation */
    },
}

pub struct Emulator {
    pub mem: mmu::MMU,
    pub reg: reg::Registers,
    dis:     zydis::Decoder,

    // for now, as a user-mode focused emulator,
    // we'll emulate fs/gs segments ourselves.
    //
    // see methods `fsbase()` and `set_fsbase()`.
    // see methods `gsbase()` and `set_gsbase()`.
    //
    // the correct way to expose this is:
    //   - x32: creating a GDT and setting the GDTR register
    //   - x64: via rdmsr/wrmsr to set the FSBASE/GSBASE registers
    //
    // if we want compat with unicorn, then may need to figure this out.
    // https://github.com/fireeye/speakeasy/blob/8c6375c67dc311f9eeb0192bb0cc452cd880372b/speakeasy/windows/winemu.py#L522
    fsbase: VA,
    gsbase: VA,
}

impl Emulator {
    pub fn with_arch(arch: Arch) -> Emulator {
        let mut decoder = match arch {
            Arch::X64 => zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64).unwrap(),
            Arch::X32 => zydis::Decoder::new(zydis::MachineMode::LEGACY_32, zydis::AddressWidth::_32).unwrap(),
        };

        // modes described here: https://github.com/zyantific/zydis/blob/5af06d64432aaa3f6af3cd3e120eefa061b790ab/include/Zydis/Decoder.h#L55
        // start with minimal until we need FULL
        decoder.enable_mode(zydis::DecoderMode::MINIMAL, false).unwrap();

        decoder.enable_mode(zydis::DecoderMode::KNC, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::MPX, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::CET, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::LZCNT, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::TZCNT, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::WBNOINVD, false).unwrap();
        decoder.enable_mode(zydis::DecoderMode::CLDEMOTE, false).unwrap();

        Emulator {
            mem:    Default::default(),
            reg:    Default::default(),
            dis:    decoder,
            fsbase: 0,
            gsbase: 0,
        }
    }

    pub fn load_module(&mut self, m: &Module) -> Result<()> {
        for section in m.sections.iter() {
            let mut page_addr = section.virtual_range.start;

            let section_size = section.virtual_range.end - section.virtual_range.start;
            self.mem.mmap(
                section.virtual_range.start,
                crate::util::align(section_size, mmu::PAGE_SIZE as u64),
                Permissions::W,
            )?;

            while page_addr < section.virtual_range.end {
                let mut page = [0u8; mmu::PAGE_SIZE];

                // AddressSpace currently allows non-page-aligned sizes.
                let page_data = if page_addr + mmu::PAGE_SIZE as u64 > section.virtual_range.end {
                    &mut page[..(section.virtual_range.end - page_addr) as usize]
                } else {
                    &mut page[..]
                };

                m.address_space.read_into(page_addr, page_data)?;
                self.mem.write_page(page_addr, &page[..])?;
                page_addr += mmu::PAGE_SIZE as u64;
            }

            self.mem.mprotect(
                section.virtual_range.start,
                crate::util::align(section_size, mmu::PAGE_SIZE as u64),
                section.permissions,
            )?;
        }

        Ok(())
    }

    pub fn from_module(m: &Module) -> Emulator {
        let mut emu = Emulator::with_arch(m.arch);
        emu.load_module(m).expect("failed to load module");
        emu
    }

    pub fn fsbase(&self) -> VA {
        self.fsbase
    }

    pub fn set_fsbase(&mut self, value: VA) {
        self.fsbase = value;
    }

    pub fn gsbase(&self) -> VA {
        self.gsbase
    }

    pub fn set_gsbase(&mut self, value: VA) {
        self.gsbase = value;
    }

    fn read_register(&self, reg: Register) -> u64 {
        use Register::*;
        match reg {
            RAX => self.reg.rax(),
            EAX => self.reg.eax() as u64,
            AX => self.reg.ax() as u64,
            AH => self.reg.ah() as u64,
            AL => self.reg.al() as u64,

            RBX => self.reg.rbx(),
            EBX => self.reg.ebx() as u64,
            BX => self.reg.bx() as u64,
            BH => self.reg.bh() as u64,
            BL => self.reg.bl() as u64,

            RCX => self.reg.rcx(),
            ECX => self.reg.ecx() as u64,
            CX => self.reg.cx() as u64,
            CH => self.reg.ch() as u64,
            CL => self.reg.cl() as u64,

            RDX => self.reg.rdx(),
            EDX => self.reg.edx() as u64,
            DX => self.reg.dx() as u64,
            DH => self.reg.dh() as u64,
            DL => self.reg.dl() as u64,

            R8 => self.reg.r8(),
            R8D => self.reg.r8d() as u64,
            R8W => self.reg.r8w() as u64,
            R8B => self.reg.r8b() as u64,

            R9 => self.reg.r9(),
            R9D => self.reg.r9d() as u64,
            R9W => self.reg.r9w() as u64,
            R9B => self.reg.r9b() as u64,

            R10 => self.reg.r10(),
            R10D => self.reg.r10d() as u64,
            R10W => self.reg.r10w() as u64,
            R10B => self.reg.r10b() as u64,

            R11 => self.reg.r11(),
            R11D => self.reg.r11d() as u64,
            R11W => self.reg.r11w() as u64,
            R11B => self.reg.r11b() as u64,

            R12 => self.reg.r12(),
            R12D => self.reg.r12d() as u64,
            R12W => self.reg.r12w() as u64,
            R12B => self.reg.r12b() as u64,

            R13 => self.reg.r13(),
            R13D => self.reg.r13d() as u64,
            R13W => self.reg.r13w() as u64,
            R13B => self.reg.r13b() as u64,

            R14 => self.reg.r14(),
            R14D => self.reg.r14d() as u64,
            R14W => self.reg.r14w() as u64,
            R14B => self.reg.r14b() as u64,

            R15 => self.reg.r15(),
            R15D => self.reg.r15d() as u64,
            R15W => self.reg.r15w() as u64,
            R15B => self.reg.r15b() as u64,

            RSI => self.reg.rsi(),
            ESI => self.reg.esi() as u64,
            SI => self.reg.si() as u64,
            SIL => self.reg.sil() as u64,

            RDI => self.reg.rdi(),
            EDI => self.reg.edi() as u64,
            DI => self.reg.di() as u64,
            DIL => self.reg.dil() as u64,

            RSP => self.reg.rsp(),
            ESP => self.reg.esp() as u64,
            SP => self.reg.sp() as u64,
            SPL => self.reg.spl() as u64,

            RBP => self.reg.rbp(),
            EBP => self.reg.ebp() as u64,
            BP => self.reg.bp() as u64,
            BPL => self.reg.bpl() as u64,

            r => unimplemented!("register: {:?}", r),
        }
    }

    fn write_register(&mut self, reg: Register, value: u64) {
        use Register::*;

        match reg {
            // a macro cannot expand to match arms,
            // which means we need to enumerate all the cases by hand. sorry.
            // https://stackoverflow.com/a/44033937/87207
            RAX => self.reg.set_rax(value),
            EAX => self.reg.set_eax(value as u32),
            AX => self.reg.set_ax(value as u16),
            AH => self.reg.set_ah(value as u8),
            AL => self.reg.set_al(value as u8),

            RBX => self.reg.set_rbx(value),
            EBX => self.reg.set_ebx(value as u32),
            BX => self.reg.set_bx(value as u16),
            BH => self.reg.set_bh(value as u8),
            BL => self.reg.set_bl(value as u8),

            RCX => self.reg.set_rcx(value),
            ECX => self.reg.set_ecx(value as u32),
            CX => self.reg.set_cx(value as u16),
            CH => self.reg.set_ch(value as u8),
            CL => self.reg.set_cl(value as u8),

            RDX => self.reg.set_rdx(value),
            EDX => self.reg.set_edx(value as u32),
            DX => self.reg.set_dx(value as u16),
            DH => self.reg.set_dh(value as u8),
            DL => self.reg.set_dl(value as u8),

            R8 => self.reg.set_r8(value),
            R8D => self.reg.set_r8d(value as u32),
            R8W => self.reg.set_r8w(value as u16),
            R8B => self.reg.set_r8b(value as u8),

            R9 => self.reg.set_r9(value),
            R9D => self.reg.set_r9d(value as u32),
            R9W => self.reg.set_r9w(value as u16),
            R9B => self.reg.set_r9b(value as u8),

            R10 => self.reg.set_r10(value),
            R10D => self.reg.set_r10d(value as u32),
            R10W => self.reg.set_r10w(value as u16),
            R10B => self.reg.set_r10b(value as u8),

            R11 => self.reg.set_r11(value),
            R11D => self.reg.set_r11d(value as u32),
            R11W => self.reg.set_r11w(value as u16),
            R11B => self.reg.set_r11b(value as u8),

            R12 => self.reg.set_r12(value),
            R12D => self.reg.set_r12d(value as u32),
            R12W => self.reg.set_r12w(value as u16),
            R12B => self.reg.set_r12b(value as u8),

            R13 => self.reg.set_r13(value),
            R13D => self.reg.set_r13d(value as u32),
            R13W => self.reg.set_r13w(value as u16),
            R13B => self.reg.set_r13b(value as u8),

            R14 => self.reg.set_r14(value),
            R14D => self.reg.set_r14d(value as u32),
            R14W => self.reg.set_r14w(value as u16),
            R14B => self.reg.set_r14b(value as u8),

            R15 => self.reg.set_r15(value),
            R15D => self.reg.set_r15d(value as u32),
            R15W => self.reg.set_r15w(value as u16),
            R15B => self.reg.set_r15b(value as u8),

            RSI => self.reg.set_rsi(value),
            ESI => self.reg.set_esi(value as u32),
            SI => self.reg.set_si(value as u16),
            SIL => self.reg.set_sil(value as u8),

            RDI => self.reg.set_rdi(value),
            EDI => self.reg.set_edi(value as u32),
            DI => self.reg.set_di(value as u16),
            DIL => self.reg.set_dil(value as u8),

            RSP => self.reg.set_rsp(value),
            ESP => self.reg.set_esp(value as u32),
            SP => self.reg.set_sp(value as u16),
            SPL => self.reg.set_spl(value as u8),

            RBP => self.reg.set_rbp(value),
            EBP => self.reg.set_ebp(value as u32),
            BP => self.reg.set_bp(value as u16),
            BPL => self.reg.set_bpl(value as u8),

            RIP => self.reg.set_rip(value),
            EIP => self.reg.set_eip(value as u32),

            r => unimplemented!("register: {:?}", r),
        }
    }

    fn get_segment_address(&self, reg: Register) -> VA {
        // see comments in `struct Emulator` about our handling of segmentation.
        // basically, we're going to take shortcuts.
        //
        // only support fs and gs segments, with easy-to-use accessors/mutators.

        use zydis::Register::*;
        match reg {
            FS => self.fsbase,
            GS => self.gsbase,
            // we don't support other segments right now.
            // so assume they're 0.
            _ => 0,
        }
    }

    fn get_operand_address(&self, op: &DecodedOperand) -> VA {
        use zydis::Register::*;
        assert!(op.ty == zydis::OperandType::MEMORY);

        // http://www.c-jump.com/CIS77/ASM/Addressing/lecture.html

        let mut addr = 0;

        addr += self.get_segment_address(op.mem.segment);

        if op.mem.base != NONE {
            if op.mem.base == RIP {
                // TODO: if RIP-relative, add insn length.
                unimplemented!("rip-relative addressing");
            } else {
                addr += self.read_register(op.mem.base);
            }
        }

        if op.mem.index != NONE {
            addr += self.read_register(op.mem.index) * (op.mem.scale as u64);
        }

        if op.mem.disp.has_displacement {
            if op.mem.disp.displacement < 0 {
                addr -= (-op.mem.disp.displacement) as u64;
            } else {
                addr += op.mem.disp.displacement as u64;
            }
        }

        addr
    }

    /// Errors:
    ///   - ReadError::AddressNotMapped when a memory address is not mapped.
    ///   - ReadError::AccessViolation when a memory address is not readable.
    fn read_memory(&self, src: &DecodedOperand) -> Result<u64, ReadError> {
        let addr = self.get_operand_address(src);

        let ret = match src.size {
            64 => self.mem.read_u64(addr),
            32 => self.mem.read_u32(addr).map(|v| v as u64),
            16 => self.mem.read_u16(addr).map(|v| v as u64),
            8 => self.mem.read_u8(addr).map(|v| v as u64),
            s => unimplemented!("memory read size: {:?}", s),
        };

        match ret {
            Ok(v) => Ok(v),
            Err(e @ mmu::MMUError::AddressNotMapped(..)) => Err(ReadError::AddressNotMapped {
                va:     addr,
                size:   src.size / 8,
                source: e,
            }),
            Err(e @ mmu::MMUError::AccessViolation(..)) => Err(ReadError::AddressNotMapped {
                va:     addr,
                size:   src.size / 8,
                source: e,
            }),
            _ => panic!("unexpected error"),
        }
    }

    /// Errors:
    ///   - WriteError::AddressNotMapped when a memory address is not mapped.
    ///   - WriteError::AccessViolation when a memory address is not writable.
    fn write_memory(&mut self, dst: &DecodedOperand, value: u64) -> Result<(), WriteError> {
        let addr = self.get_operand_address(dst);

        let ret = match dst.size {
            64 => self.mem.write_u64(addr, value),
            32 => self.mem.write_u32(addr, value as u32),
            16 => self.mem.write_u16(addr, value as u16),
            8 => self.mem.write_u8(addr, value as u8),
            s => unimplemented!("memory write size: {:?}", s),
        };

        match ret {
            Ok(()) => Ok(()),
            Err(e @ mmu::MMUError::AddressNotMapped(..)) => Err(WriteError::AddressNotMapped {
                va:     addr,
                size:   dst.size / 8,
                source: e,
            }),
            Err(e @ mmu::MMUError::AccessViolation(..)) => Err(WriteError::AccessViolation {
                va:     addr,
                size:   dst.size / 8,
                source: e,
            }),
            _ => panic!("unexpected error"),
        }
    }

    /// Errors:
    ///   - ReadError::AddressNotMapped when a memory address is not mapped.
    ///   - ReadError::AccessViolation when a memory address is not readable.
    fn read_operand(&mut self, insn: &DecodedInstruction, src: &DecodedOperand) -> Result<u64, ReadError> {
        use zydis::enums::OperandType::*;
        Ok(match src.ty {
            IMMEDIATE => {
                if src.imm.is_relative {
                    self.reg.rip + insn.length as u64 + src.imm.value
                } else {
                    src.imm.value
                }
            }
            REGISTER => self.read_register(src.reg),
            // handle unmapped read
            MEMORY => self.read_memory(src)?,
            t => unimplemented!("read operand type: {:?}", t),
        })
    }

    /// Errors:
    ///   - WriteError::AddressNotMapped when a memory address is not mapped.
    ///   - WriteError::AccessViolation when a memory address is not executable.
    fn write_operand(&mut self, dst: &DecodedOperand, value: u64) -> Result<(), WriteError> {
        use zydis::enums::OperandType::*;

        match dst.ty {
            REGISTER => self.write_register(dst.reg, value),
            MEMORY => self.write_memory(dst, value)?,
            t => unimplemented!("write operand type: {:?}", t),
        }

        Ok(())
    }

    /// Errors:
    ///   - FetchError::InvalidInstruction for instructions that cannot be
    ///     decoded.
    ///   - FetchError::AddressNotMapped when the instruction address is not
    ///     mapped.
    ///   - FetchError::AccessViolation when the instruction address is not
    ///     executable.
    pub fn fetch(&mut self) -> Result<zydis::DecodedInstruction, FetchError> {
        let pc = self.reg.rip;
        debug!("emu: fetch: {:#x}", pc);

        let buf = match self.mem.fetch(pc) {
            Ok(buf) => buf,
            Err(e @ mmu::MMUError::AddressNotMapped(..)) => {
                return Err(FetchError::AddressNotMapped { va: pc, source: e })
            }
            Err(e @ mmu::MMUError::AccessViolation(..)) => {
                return Err(FetchError::AccessViolation { va: pc, source: e })
            }
            _ => panic!("unexpected error"),
        };

        if let Ok(Some(insn)) = self.dis.decode(&buf[..]) {
            Ok(insn)
        } else {
            Err(FetchError::InvalidInstruction(pc))
        }
    }

    /// Errors:
    ///   - WriteError::AddressNotMapped when a memory address is not mapped.
    ///   - WriteError::AccessViolation when a memory address is not executable.
    ///   - ReadError::AddressNotMapped when a memory address is not mapped.
    ///   - ReadError::AccessViolation when a memory address is not readable.
    ///
    /// care is taken that when an error occurs, the caller may handle it and
    /// re-try to execute it.
    /// that is, the caller may page in some additional memory, for example,
    /// and then invoke this routine again.
    pub fn execute(&mut self, insn: &DecodedInstruction) -> Result<()> {
        use zydis::enums::{Mnemonic::*, Register::*};

        debug!("emu: insn: {:#x}: {:#?}", self.reg.rip, insn.mnemonic);
        match insn.mnemonic {
            NOP => {
                //println!("{:#?}", insn);
                self.reg.rip += insn.length as u64;
            }

            MOV => {
                let dst = &insn.operands[0];
                let src = &insn.operands[1];

                let value = self.read_operand(insn, src)?;
                self.write_operand(dst, value)?;

                self.reg.rip += insn.length as u64;
            }

            XCHG => {
                let m = &insn.operands[0];
                let n = &insn.operands[1];

                let mm = self.read_operand(insn, m)?;
                let nn = self.read_operand(insn, n)?;
                self.write_operand(m, nn)?;
                self.write_operand(n, mm)?;

                self.reg.rip += insn.length as u64;
            }

            LEA => {
                let dst = &insn.operands[0];
                let src = &insn.operands[1];

                let value = self.get_operand_address(src);
                self.write_operand(dst, value)?;

                self.reg.rip += insn.length as u64;
            }

            PUSH => {
                // EXPLICIT/READ/IMMEDIATE/REGISTER
                let src = &insn.operands[0];

                // HIDDEN/WRITE/REG/$SP
                let sp_op = &insn.operands[1];
                assert!(sp_op.ty == zydis::enums::OperandType::REGISTER);

                // HIDDEN/WRITE/MEM
                let dst = &insn.operands[2];
                assert!(dst.ty == zydis::enums::OperandType::MEMORY);

                // > "The PUSH ESP instruction pushes the value of
                // > the ESP register as it existed before the
                // > instruction was executed."
                //
                // https://c9x.me/x86/html/file_module_x86_id_269.html
                let value = self.read_operand(insn, src)?;

                match sp_op.reg {
                    RSP => self.reg.rsp -= 8,
                    ESP => self.reg.rsp -= 4,
                    _ => unimplemented!(),
                }

                if let Err(e) = self.write_operand(dst, value) {
                    // roll back the stack changes
                    match sp_op.reg {
                        RSP => self.reg.rsp += 8,
                        ESP => self.reg.rsp += 4,
                        _ => unimplemented!(),
                    }
                    return Err(e.into());
                }

                self.reg.rip += insn.length as u64;
            }

            POP => {
                // EXPLICIT/write/REGISTER
                let dst = &insn.operands[0];

                // HIDDEN/WRITE/REG/$SP
                let sp_op = &insn.operands[1];
                assert!(sp_op.ty == zydis::enums::OperandType::REGISTER);

                // HIDDEN/READ/MEM
                let src = &insn.operands[2];
                assert!(src.ty == zydis::enums::OperandType::MEMORY);

                let value = self.read_operand(insn, src)?;

                // > "The POP ESP instruction increments the
                // > stack pointer (ESP) before data at the
                // > old top of stack is written into the destination."
                //
                // https://c9x.me/x86/html/file_module_x86_id_248.html
                match sp_op.reg {
                    RSP => self.reg.rsp += 8,
                    ESP => self.reg.rsp += 4,
                    _ => unimplemented!(),
                }

                if let Err(e) = self.write_operand(dst, value) {
                    // roll back the stack changes
                    match sp_op.reg {
                        RSP => self.reg.rsp -= 8,
                        ESP => self.reg.rsp -= 4,
                        _ => unimplemented!(),
                    }
                    return Err(e.into());
                }

                self.reg.rip += insn.length as u64;
            }

            CALL => {
                // EXPLICIT/READ/MEMORY/REGISTER call target
                let target = &insn.operands[0];
                // HIDDEN/READ-WRITE/REGISTER/PC program counter
                let pc = &insn.operands[1];
                assert!(pc.ty == zydis::enums::OperandType::REGISTER);
                // HIDDEN/READ-WRITE/REGISTER/SP stack pointer
                let sp = &insn.operands[2];
                assert!(sp.ty == zydis::enums::OperandType::REGISTER);
                // HIDDEN/READ-WRITE/MEMORY/SP stack contents
                let stack = &insn.operands[3];
                assert!(stack.ty == zydis::enums::OperandType::MEMORY);

                match sp.reg {
                    RSP => self.reg.rsp -= 8,
                    ESP => self.reg.rsp -= 4,
                    _ => unimplemented!(),
                }

                let return_address = self.reg.rip + insn.length as u64;
                self.write_operand(stack, return_address)?;

                if let Err(e) = self.write_operand(stack, return_address) {
                    // roll back the stack changes
                    match sp.reg {
                        RSP => self.reg.rsp += 8,
                        ESP => self.reg.rsp += 4,
                        _ => unimplemented!(),
                    }
                    return Err(e.into());
                }

                // these read/writes shouldn't ever fail: address computation and PC register
                // set.
                let target_addr = self.read_operand(insn, target).expect("failed to read call target");
                self.write_operand(pc, target_addr).expect("failed to set PC");
            }

            RET => {
                // HIDDEN/WRITE/REGISTER/PC
                let pc = &insn.operands[0];
                assert!(pc.ty == zydis::enums::OperandType::REGISTER);
                // HIDDEN/READ-WRITE/REGISTER/SP
                let sp = &insn.operands[1];
                assert!(sp.ty == zydis::enums::OperandType::REGISTER);
                // HIDDEN/READ/MEMORY/SP stack contents
                let stack = &insn.operands[2];
                assert!(stack.ty == zydis::enums::OperandType::MEMORY);

                let return_address = self.read_operand(insn, stack)?;

                match sp.reg {
                    RSP => self.reg.rsp += 8,
                    ESP => self.reg.rsp += 4,
                    _ => unimplemented!(),
                }

                // this write shouldn't ever fail: PC register set.
                self.write_operand(pc, return_address).expect("failed to set PC");
            }

            SUB => {
                // EXPLICIT/READ/WRITE
                let dst = &insn.operands[0];
                // EXPLICIT/READ
                let src = &insn.operands[1];
                // EXPLICIT/WRITE/RFLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = self.read_operand(insn, dst)?;
                let n = self.read_operand(insn, src)?;

                let (result, msb_index, cf) = match dst.size {
                    64 => {
                        let result = m.wrapping_sub(n);
                        (result, 63, n > m)
                    }
                    32 => {
                        let result = (m as u32).wrapping_sub(n as u32) as u64;
                        (result, 31, n as u32 > m as u32)
                    }
                    16 => {
                        let result = (m as u16).wrapping_sub(n as u16) as u64;
                        (result, 15, n as u16 > m as u16)
                    }
                    8 => {
                        let result = (m as u8).wrapping_sub(n as u8) as u64;
                        (result, 7, n as u8 > m as u8)
                    }
                    s => unimplemented!("sub size {:}", s),
                };

                let zf = result == 0;
                let pf = (result as u8).count_ones() % 2 == 0;
                let sf = (result & (1 << msb_index)) > 0;

                // ```text
                // > The rules for turning on the overflow flag in binary/integer math are two:
                // >
                // > 1. If the sum of two numbers with the sign bits off yields a result number
                // >   with the sign bit on, the "overflow" flag is turned on.
                // >
                // >   0100 + 0100 = 1000 (overflow flag is turned on)
                // >
                // > 2. If the sum of two numbers with the sign bits on yields a result number
                // >   with the sign bit off, the "overflow" flag is turned on.
                // >
                // >   1000 + 1000 = 0000 (overflow flag is turned on)
                // ```
                // http://teaching.idallen.com/dat2343/10f/notes/040_overflow.txt

                let m_msb = (m & (1 << msb_index)) > 0;
                let n_msb = (n & (1 << msb_index)) > 0;

                // ```text
                // >       SUBTRACTION SIGN BITS
                // >     num1sign num2sign sumsign
                // >    ---------------------------
                // >         0 0 0
                // >         0 0 1
                // >         0 1 0
                // >  *OVER* 0 1 1 (subtracting a negative is the same as adding a positive)
                // >  *OVER* 1 0 0 (subtracting a positive is the same as adding a negative)
                // >         1 0 1
                // >         1 1 0
                // >         1 1 1
                // ```
                // http://teaching.idallen.com/dat2343/10f/notes/040_overflow.txt
                let of = matches!((m_msb, n_msb, sf), (false, true, true) | (true, false, false));

                // https://stackoverflow.com/a/4513781/87207
                let af = (n & 0x0F) > (m & 0x0F);

                self.write_operand(dst, result)?;
                self.reg.set_cf(cf);
                self.reg.set_of(of);
                self.reg.set_sf(sf);
                self.reg.set_af(af);
                self.reg.set_pf(pf);
                self.reg.set_zf(zf);

                self.reg.rip += insn.length as u64;
            }

            ADD => {
                // EXPLICIT/READ/WRITE
                let dst = &insn.operands[0];
                // EXPLICIT/READ
                let src = &insn.operands[1];
                // HIDDEN/WRITE/RFLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = self.read_operand(insn, dst)?;
                let n = self.read_operand(insn, src)?;

                let (result, msb_index, cf) = match dst.size {
                    64 => {
                        let result = n as u128 + m as u128;
                        (result as u64 & u64::MAX, 63, result > u64::MAX as u128)
                    }
                    32 => {
                        let result = (n as u32) as u64 + (m as u32) as u64;
                        (result & u32::MAX as u64, 31, result > u32::MAX as u64)
                    }
                    16 => {
                        let result = (n as u16) as u32 + (m as u16) as u32;
                        (result as u64 & u16::MAX as u64, 15, result > u16::MAX as u32)
                    }
                    8 => {
                        let result = (n as u8) as u16 + (m as u8) as u16;
                        (result as u64 & u8::MAX as u64, 7, result > u8::MAX as u16)
                    }
                    s => unimplemented!("sub size {:}", s),
                };

                let zf = result == 0;
                let pf = (result as u8).count_ones() % 2 == 0;
                let sf = (result & (1 << msb_index)) > 0;

                let m_msb = (m & (1 << msb_index)) > 0;
                let n_msb = (n & (1 << msb_index)) > 0;

                // ```text
                // >        ADDITION SIGN BITS
                // >     num1sign num2sign sumsign
                // >    ---------------------------
                // >         0 0 0
                // >  *OVER* 0 0 1 (adding two positives should be positive)
                // >         0 1 0
                // >         0 1 1
                // >         1 0 0
                // >         1 0 1
                // >  *OVER* 1 1 0 (adding two negatives should be negative)
                // >         1 1 1
                // ```
                // http://teaching.idallen.com/dat2343/10f/notes/040_overflow.txt
                let of = matches!((m_msb, n_msb, sf), (false, false, true) | (true, true, false));

                // https://stackoverflow.com/a/4513781/87207
                let af = (((n & 0x0F) + (m & 0x0F)) & 0xF0) > 0;

                self.write_operand(dst, result)?;
                self.reg.set_cf(cf);
                self.reg.set_of(of);
                self.reg.set_sf(sf);
                self.reg.set_af(af);
                self.reg.set_pf(pf);
                self.reg.set_zf(zf);

                self.reg.rip += insn.length as u64;
            }

            CMP => {
                // EXPLICIT/READ
                let dst = &insn.operands[0];
                // EXPLICIT/READ
                let src = &insn.operands[1];
                // HIDDEN/WRITE/RFLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = self.read_operand(insn, dst)?;
                let n = self.read_operand(insn, src)?;

                // this is a copy-pasta of SUB,
                // with the exception that the destination is not written to.
                let (result, msb_index, cf) = match dst.size {
                    64 => {
                        let result = m.wrapping_sub(n);
                        (result, 63, n > m)
                    }
                    32 => {
                        let result = (m as u32).wrapping_sub(n as u32) as u64;
                        (result, 31, n as u32 > m as u32)
                    }
                    16 => {
                        let result = (m as u16).wrapping_sub(n as u16) as u64;
                        (result, 15, n as u16 > m as u16)
                    }
                    8 => {
                        let result = (m as u8).wrapping_sub(n as u8) as u64;
                        (result, 7, n as u8 > m as u8)
                    }
                    s => unimplemented!("cmp size {:}", s),
                };

                let zf = result == 0;
                let pf = (result as u8).count_ones() % 2 == 0;
                let sf = (result & (1 << msb_index)) > 0;
                let m_msb = (m & (1 << msb_index)) > 0;
                let n_msb = (n & (1 << msb_index)) > 0;
                let of = matches!((m_msb, n_msb, sf), (false, true, true) | (true, false, false));
                let af = (n & 0x0F) > (m & 0x0F);

                self.reg.set_cf(cf);
                self.reg.set_of(of);
                self.reg.set_sf(sf);
                self.reg.set_af(af);
                self.reg.set_pf(pf);
                self.reg.set_zf(zf);

                self.reg.rip += insn.length as u64;
            }

            JNB => {
                // EXPLICIT/READ/IMMEDIATE target
                let target = &insn.operands[0];
                // HIDDEN/READ-WRITE/REGISTER/PC
                let pc = &insn.operands[1];
                assert!(pc.ty == zydis::enums::OperandType::REGISTER);
                // HIDDEN/READ/REGISTER/FLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                if !self.reg.cf() {
                    self.reg.rip = self.read_operand(insn, target)?;
                } else {
                    self.reg.rip += insn.length as u64;
                }
            }

            NEG => {
                // EXPLICIT/READ-WRITE dst
                let dst = &insn.operands[0];
                // HIDDEN/WRITE/RFLAGS
                let flags = &insn.operands[1];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = 0u64;
                let n = self.read_operand(insn, dst)?;

                // this is a copy-pasta of SUB,
                // with the exception that the destination is not written to.
                let (result, msb_index, cf) = match dst.size {
                    64 => {
                        let result = m.wrapping_sub(n);
                        (result, 63, n > m)
                    }
                    32 => {
                        let result = (m as u32).wrapping_sub(n as u32) as u64;
                        (result, 31, n as u32 > m as u32)
                    }
                    16 => {
                        let result = (m as u16).wrapping_sub(n as u16) as u64;
                        (result, 15, n as u16 > m as u16)
                    }
                    8 => {
                        let result = (m as u8).wrapping_sub(n as u8) as u64;
                        (result, 7, n as u8 > m as u8)
                    }
                    s => unimplemented!("cmp size {:}", s),
                };

                self.write_operand(dst, result)?;
                let zf = result == 0;
                let pf = (result as u8).count_ones() % 2 == 0;
                let sf = (result & (1 << msb_index)) > 0;
                let m_msb = (m & (1 << msb_index)) > 0;
                let n_msb = (n & (1 << msb_index)) > 0;
                let of = matches!((m_msb, n_msb, sf), (false, true, true) | (true, false, false));
                let af = (n & 0x0F) > (m & 0x0F);

                self.reg.set_cf(cf);
                self.reg.set_of(of);
                self.reg.set_sf(sf);
                self.reg.set_af(af);
                self.reg.set_pf(pf);
                self.reg.set_zf(zf);

                self.reg.rip += insn.length as u64;
            }

            TEST => {
                // EXPLICIT/READ
                let m = &insn.operands[0];
                let size = m.size;
                // EXPLICIT/READ
                let n = &insn.operands[1];
                // HIDDEN/WRITE/RFLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = self.read_operand(insn, m)?;
                let n = self.read_operand(insn, n)?;

                let (result, msb_index) = match size {
                    64 => {
                        let result = m & n;
                        (result, 63)
                    }
                    32 => {
                        let result = ((m as u32) & (n as u32)) as u64;
                        (result, 31)
                    }
                    16 => {
                        let result = ((m as u16) & (n as u16)) as u64;
                        (result, 15)
                    }
                    8 => {
                        let result = ((m as u8) & (n as u8)) as u64;
                        (result, 7)
                    }
                    s => unimplemented!("cmp size {:}", s),
                };

                let zf = result == 0;
                let pf = (result as u8).count_ones() % 2 == 0;
                let sf = (result & (1 << msb_index)) > 0;

                self.reg.set_sf(sf);
                self.reg.set_pf(pf);
                self.reg.set_zf(zf);

                self.reg.set_cf(false);
                self.reg.set_of(false);
                // AF is undefined
                // self.reg.set_af(af);

                self.reg.rip += insn.length as u64;
            }

            m => {
                unimplemented!("mnemonic: {:?}", m);
                //self.reg.rip += insn.length as u64;
            }
        }

        Ok(())
    }

    /// Errors:
    ///   - FetchError::InvalidInstruction for instructions that cannot be
    ///     decoded.
    ///   - FetchError::AddressNotMapped when the instruction address is not
    ///     mapped.
    ///   - FetchError::AccessViolation when the instruction address is not
    ///     executable.
    ///   - WriteError::AddressNotMapped when a memory address is not mapped.
    ///   - WriteError::AccessViolation when a memory address is not executable.
    ///   - ReadError::AddressNotMapped when a memory address is not mapped.
    ///   - ReadError::AccessViolation when a memory address is not readable.
    ///
    /// TODO: this routine should not be part of the base emulator.
    /// there are too many customizations to handle, like how to deal with
    /// imports, styles of breakpoints, etc.
    /// so, provide documentation/examples of `step` routines and remove this.
    pub fn step(&mut self) -> Result<()> {
        debug!("emu: step: {:#x}", self.reg.rip);

        let insn = self.fetch()?;
        self.execute(&insn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{emu::*, test::*};

    use dynasmrt::{dynasm, DynasmApi};

    const BASE_ADDRESS: u64 = 0x1000;

    #[test]
    fn raw_create() -> Result<()> {
        //init_logging();

        let mut emu: Emulator = Emulator::with_arch(Arch::X64);

        emu.mem.mmap(BASE_ADDRESS, 0x1000, Permissions::RWX)?;

        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let code = b"\x48\xC7\xC0\x01\x00\x00\x00";
        emu.mem.write(BASE_ADDRESS, &code[..])?;

        emu.reg.rip = BASE_ADDRESS;
        emu.step()?;

        assert_eq!(emu.reg.rip, BASE_ADDRESS + 0x7);
        assert_eq!(emu.reg.rax, 1);

        Ok(())
    }

    #[test]
    fn from_module() -> Result<()> {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let m = load_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);

        let mut emu = Emulator::from_module(&m);
        emu.reg.rip = m.address_space.base_address;
        emu.step()?;

        assert_eq!(emu.reg.rip, m.address_space.base_address + 0x7);
        assert_eq!(emu.reg.rax, 1);

        Ok(())
    }

    #[test]
    fn rw_reg() -> Result<()> {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
        emu.step()?;
        assert_eq!(emu.reg.rax, 1);

        // 0:  b8 01 00 00 00          mov    eax,0x1
        let mut emu = emu_from_shellcode64(&b"\xB8\x01\x00\x00\x00"[..]);
        emu.reg.rax = 0xFFFF_FFFF_FFFF_FFFF;
        emu.step()?;
        assert_eq!(emu.reg.eax(), 1);
        assert_eq!(emu.reg.rax(), 0x1);

        // 0:  66 b8 01 00             mov    ax,0x1
        let mut emu = emu_from_shellcode64(&b"\x66\xB8\x01\x00"[..]);
        emu.reg.rax = 0xFFFF_FFFF_FFFF_FFFF;
        emu.step()?;
        assert_eq!(emu.reg.ax(), 1);
        assert_eq!(emu.reg.eax(), 0xFFFF_0001);
        assert_eq!(emu.reg.rax(), 0xFFFF_FFFF_FFFF_0001);

        // 0:  b0 01                   mov    al,0x1
        let mut emu = emu_from_shellcode64(&b"\xB0\x01"[..]);
        emu.reg.rax = 0xFFFF_FFFF_FFFF_FFFF;
        emu.step()?;
        assert_eq!(emu.reg.al(), 1);
        assert_eq!(emu.reg.ax(), 0xFF01);
        assert_eq!(emu.reg.eax(), 0xFFFF_FF01);
        assert_eq!(emu.reg.rax(), 0xFFFF_FFFF_FFFF_FF01);

        // 0:  b4 01                   mov    ah,0x1
        let mut emu = emu_from_shellcode64(&b"\xB4\x01"[..]);
        emu.reg.rax = 0xFFFF_FFFF_FFFF_FFFF;
        emu.step()?;
        assert_eq!(emu.reg.ah(), 1);
        assert_eq!(emu.reg.ax(), 0x01FF);
        assert_eq!(emu.reg.eax(), 0xFFFF_01FF);
        assert_eq!(emu.reg.rax(), 0xFFFF_FFFF_FFFF_01FF);

        // 0:  48 89 c3                mov    rbx,rax
        let mut emu = emu_from_shellcode64(&b"\x48\x89\xC3"[..]);
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.reg.rbx(), 0x1122_3344_5566_7788);

        // 0:  89 c3                   mov    ebx,eax
        let mut emu = emu_from_shellcode64(&b"\x89\xC3"[..]);
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.reg.ebx(), 0x5566_7788);

        // 0:  66 89 c3                mov    bx,ax
        let mut emu = emu_from_shellcode64(&b"\x66\x89\xC3"[..]);
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.reg.bx(), 0x7788);

        // 0:  88 c3                   mov    bl,al
        let mut emu = emu_from_shellcode64(&b"\x88\xC3"[..]);
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.reg.bl(), 0x88);

        // 0:  88 e7                   mov    bh,ah
        let mut emu = emu_from_shellcode64(&b"\x88\xE7"[..]);
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.reg.bh(), 0x77);

        Ok(())
    }

    #[test]
    fn rw_mem() -> Result<()> {
        // 0:  48 8b 04 25 00 80 00 00   mov    rax,QWORD PTR ds:0x8000
        let mut emu = emu_from_shellcode64(&b"\x48\x8B\x04\x25\x00\x80\x00\x00"[..]);
        emu.mem.mmap(0x8000, 0x1000, Permissions::RW)?;
        emu.mem.write_u64(0x8000, 0x1122_3344_5566_7788)?;
        emu.step()?;
        assert_eq!(emu.reg.rax(), 0x1122_3344_5566_7788);

        // 0:  8b 04 25 00 80 00 00    mov    eax,DWORD PTR ds:0x8000
        let mut emu = emu_from_shellcode64(&b"\x8B\x04\x25\x00\x80\x00\x00"[..]);
        emu.mem.mmap(0x8000, 0x1000, Permissions::RW)?;
        emu.mem.write_u64(0x8000, 0x1122_3344_5566_7788)?;
        emu.step()?;
        assert_eq!(emu.reg.rax(), 0x5566_7788);

        // 0:  48 89 04 25 00 80 00 00   mov    QWORD PTR ds:0x8000,rax
        let mut emu = emu_from_shellcode64(&b"\x48\x89\x04\x25\x00\x80\x00\x00"[..]);
        emu.mem.mmap(0x8000, 0x1000, Permissions::RW)?;
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.mem.read_u64(0x8000)?, 0x1122_3344_5566_7788);

        // 0:  89 04 25 00 80 00 00    mov    DWORD PTR ds:0x8000,eax
        let mut emu = emu_from_shellcode64(&b"\x89\x04\x25\x00\x80\x00\x00"[..]);
        emu.mem.mmap(0x8000, 0x1000, Permissions::RW)?;
        emu.reg.rax = 0x1122_3344_5566_7788;
        emu.step()?;
        assert_eq!(emu.mem.read_u32(0x8000)?, 0x5566_7788);

        Ok(())
    }

    #[test]
    fn uc_check() {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let mut uc = uc::uc_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
        uc.step().unwrap();

        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
        emu.step().unwrap();

        uc.check(&emu);
    }

    #[test]
    fn uc_check_failure() {
        // would want to use `#[should_panic]`
        // however it still prints the panic stack trace
        // which makes it look like the test failed.
        // so we'll catch the panic ourselves.

        // hide the panic stack trace
        // ref: https://stackoverflow.com/a/35559417/87207
        std::panic::set_hook(Box::new(|_info| {
            // explicitly exit with zero status (success).
            // this is necessary because the unwind is not guaranteed to be caught.
            // but this hook will be invoked. so now's our chance to say things are ok.
            std::process::exit(0);
        }));

        // catch expected panic
        // ref: https://stackoverflow.com/a/42649833/87207
        assert!(
            // this doesn't work under cranelift (at least today),
            // probably because it doesn't support unwinding.
            std::panic::catch_unwind(|| {
                // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
                let mut uc = uc::uc_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
                uc.step().unwrap();

                // 0:  48 c7 c0 01 00 00 00    mov    rax,0x2
                let mut emu = emu_from_shellcode64(&b"\x48\xC7\xC0\x02\x00\x00\x00"[..]);
                emu.step().unwrap();

                // 1 vs 2 -> failure
                uc.check(&emu);
            })
            .is_err(),
            "should have failed the uc.check"
        );
    }

    /// emulate the given code using both Unicorn and our emulator,
    /// checking the state of the system after each step.
    fn emu_check(code: &[u8]) {
        let mut uc = uc::uc_from_shellcode64(code);
        let mut emu = emu_from_shellcode64(code);

        loop {
            uc.step().unwrap();
            emu.step().unwrap();
            uc.check(&emu);

            // assume that the instructions are padded with NULLs
            // and when we hit them, the testcase is done.
            if emu.mem.read_u64(emu.reg.rip()).unwrap() == 0 {
                break;
            }
        }
    }

    #[test]
    fn test_uc_check() {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        emu_check(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
    }

    #[test]
    fn dynasm_assembly() {
        // test 1: assembly matches defuse.ca
        let mut ops = dynasmrt::x64::Assembler::new().unwrap();
        dynasm!(ops
            ; .arch x64
            ; mov rax, 0x1
            ; sub rax, 0x1
        );
        let buf = ops.finalize().unwrap();
        assert_eq!(&buf[..], &b"\x48\xC7\xC0\x01\x00\x00\x00\x48\x83\xE8\x01"[..]);
        emu_check(&buf);

        // test 2: easy to emulate it
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; sub rax, 0x1
            );
        });
    }

    /// assemble and emulate the given assembly,
    /// comparing unicorn to our emulator at each step.
    fn emu_check_with_asm<F>(f: F)
    where
        F: Fn(&mut dynasmrt::Assembler<dynasmrt::x64::X64Relocation>),
    {
        let mut ops = dynasmrt::x64::Assembler::new().unwrap();
        f(&mut ops);
        let buf = ops.finalize().unwrap();
        emu_check(&buf);
    }

    #[test]
    fn insn_mov() {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x80
                ; lea rbx, [rax+0x4]
                ; mov    rax,0x1
                ; mov    rbx,rax
                ; mov    rcx,-1
                ; mov    ecx,ebx
                ; mov    rcx,-1
                ; mov    cx,bx
                ; mov    rcx,-1
                ; mov    cl,bl
                ; mov    [rbp - 4], rax
                ; mov    rbx, [rbp - 4]
            );
        });
    }

    #[test]
    fn insn_xchg() {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x80
                ; mov rbx, 0x10
                ; xchg rax, rbx
            );
        });
    }

    #[test]
    fn insn_lea() {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x80
                ; lea rbx, [rax+0x4]
            );
        });
    }

    const INTERESTING_NUMBERS: [i64; 61] = [
        i64::MIN,
        i64::MIN + 1,
        (i32::MIN as i64) - 1,
        i32::MIN as i64,
        (i32::MIN as i64) + 1,
        (i16::MIN as i64) - 1,
        i16::MIN as i64,
        (i16::MIN as i64) + 1,
        (i8::MIN as i64) - 1,
        i8::MIN as i64,
        (i8::MIN as i64) + 1,
        -65,
        -64,
        -63,
        -42,
        -69,
        -1337,
        -33,
        -32,
        -31,
        -17,
        -16,
        -15,
        -9,
        -8,
        -7,
        -2,
        -1,
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        15,
        16,
        17,
        31,
        32,
        33,
        42,
        69,
        1337,
        63,
        64,
        65,
        (i8::MAX - 1) as i64,
        i8::MAX as i64,
        (i8::MAX as i64) + 1,
        (i16::MAX - 1) as i64,
        i16::MAX as i64,
        (i16::MAX as i64) + 1,
        (i32::MAX - 1) as i64,
        i32::MAX as i64,
        (i32::MAX as i64) + 1,
        i64::MAX - 1,
        i64::MAX,
    ];

    #[test]
    fn insn_sub() -> Result<()> {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; sub rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x2
                ; sub rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x0
                ; sub rax, 0x1
            );
        });

        for &i in INTERESTING_NUMBERS.iter() {
            for &j in INTERESTING_NUMBERS.iter() {
                emu_check_with_asm(|ops| {
                    dynasm!(ops
                        ; .arch x64
                        ; mov al, i as i8
                        ; sub al, j as i8

                        ; mov ax, i as i16
                        ; sub ax, j as i16

                        ; mov eax, i as i32
                        ; sub eax, j as i32

                        // there is no `sub reg64, imm64`
                        // only `sub reg64, reg64`
                        ; mov rax, QWORD i
                        ; mov rbx, QWORD j
                        ; sub rax, rbx
                    );
                });
            }
        }

        Ok(())
    }

    #[test]
    fn insn_add() -> Result<()> {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; add rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x2
                ; add rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, -1
                ; add rax, 0x1
            );
        });

        for &i in INTERESTING_NUMBERS.iter() {
            for &j in INTERESTING_NUMBERS.iter() {
                emu_check_with_asm(|ops| {
                    dynasm!(ops
                        ; .arch x64
                        ; mov al, i as i8
                        ; add al, j as i8

                        ; mov ax, i as i16
                        ; add ax, j as i16

                        ; mov eax, i as i32
                        ; add eax, j as i32

                        ; mov rax, QWORD i
                        ; mov rbx, QWORD j
                        ; add rax, rbx
                    );
                });
            }
        }

        Ok(())
    }

    #[test]
    fn insn_cmp() -> Result<()> {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; cmp rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x2
                ; cmp rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, -1
                ; cmp rax, 0x1
            );
        });

        for &i in INTERESTING_NUMBERS.iter() {
            for &j in INTERESTING_NUMBERS.iter() {
                emu_check_with_asm(|ops| {
                    dynasm!(ops
                        ; .arch x64
                        ; mov al, i as i8
                        ; cmp al, j as i8

                        ; mov ax, i as i16
                        ; cmp ax, j as i16

                        ; mov eax, i as i32
                        ; cmp eax, j as i32

                        ; mov rax, QWORD i
                        ; mov rbx, QWORD j
                        ; cmp rax, rbx
                    );
                });
            }
        }

        Ok(())
    }

    #[test]
    fn insn_test() -> Result<()> {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; test rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x2
                ; test rax, 0x1
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, -1
                ; test rax, 0x1
            );
        });

        for &i in INTERESTING_NUMBERS.iter() {
            for &j in INTERESTING_NUMBERS.iter() {
                emu_check_with_asm(|ops| {
                    dynasm!(ops
                        ; .arch x64
                        ; mov al, i as i8
                        ; test al, j as i8

                        ; mov ax, i as i16
                        ; test ax, j as i16

                        ; mov eax, i as i32
                        ; test eax, j as i32

                        ; mov rax, QWORD i
                        ; mov rbx, QWORD j
                        ; test rax, rbx
                    );
                });
            }
        }

        Ok(())
    }

    #[test]
    fn insn_jnb() {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        // 7:  48 83 f8 00             cmp    rax,0x0
        // b:  73 01                   jnb    e <_main+0xe>
        // d:  90                      nop
        // e:  48 c7 c0 01 00 00 00    mov    rax,0x1
        // 15: 48 83 f8 01             cmp    rax,0x1
        // 19: 73 01                   jnb    1c <_main+0x1c>
        // 1b: 90                      nop
        // 1c: 48 c7 c0 01 00 00 00    mov    rax,0x1
        // 23: 48 83 f8 02             cmp    rax,0x2
        // 27: 73 01                   jnb    2a <_main+0x2a>
        // 29: 90                      nop
        emu_check(&b"\x48\xC7\xC0\x01\x00\x00\x00\x48\x83\xF8\x00\x73\x01\x90\x48\xC7\xC0\x01\x00\x00\x00\x48\x83\xF8\x01\x73\x01\x90\x48\xC7\xC0\x01\x00\x00\x00\x48\x83\xF8\x02\x73\x01\x90"[..]);
    }

    #[test]
    fn insn_neg() -> Result<()> {
        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0x1
                ; neg rax
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, -1
                ; neg rax
            );
        });

        emu_check_with_asm(|ops| {
            dynasm!(ops
                ; .arch x64
                ; mov rax, 0
                ; neg rax
            );
        });

        for &i in INTERESTING_NUMBERS.iter() {
            emu_check_with_asm(|ops| {
                dynasm!(ops
                    ; .arch x64
                    ; mov al, i as i8
                    ; neg al

                    ; mov ax, i as i16
                    ; neg ax

                    ; mov eax, i as i32
                    ; neg eax

                    ; mov rax, QWORD i
                    ; neg rax
                );
            });
        }

        Ok(())
    }

    #[test]
    fn insn_push_pop() {
        // 0:  6a 01                   push   0x1
        // 2:  58                      pop    rax
        emu_check(&b"\x6A\x01\x58"[..]);
    }

    #[test]
    fn insn_call() -> Result<()> {
        // 0:  e8 00 00 00 00          call   $+5
        emu_check(&b"\xE8\x00\x00\x00\x00"[..]);

        // 0:  48 c7 c0 80 00 00 00    mov    rax,0x80
        // 7:  ff d0                   call   rax
        emu_check(&b"\x48\xC7\xC0\x80\x00\x00\x00\xFF\xD0"[..]);

        // 0:  c7 04 25 40 00 00 00    mov    DWORD PTR ds:0x40,0x80
        // 7:  80 00 00 00
        // b:  ff 14 25 40 00 00 00    call   QWORD PTR ds:0x40
        emu_check(&b"\xC7\x04\x25\x40\x00\x00\x00\x80\x00\x00\x00\xFF\x14\x25\x40\x00\x00\x00"[..]);

        // 0:  c7 04 25 40 00 00 00    mov    DWORD PTR ds:0x40,0x70
        // 7:  70 00 00 00
        // b:  c7 04 25 48 00 00 00    mov    DWORD PTR ds:0x48,0x80
        // 12: 80 00 00 00
        // 16: 48 c7 c0 40 00 00 00    mov    rax,0x40
        // 1d: ff 50 08                call   QWORD PTR [rax+0x8]
        emu_check(&b"\xC7\x04\x25\x40\x00\x00\x00\x70\x00\x00\x00\xC7\x04\x25\x48\x00\x00\x00\x80\x00\x00\x00\x48\xC7\xC0\x40\x00\x00\x00\xFF\x50\x08"[..]);

        Ok(())
    }

    #[test]
    fn insn_ret() {
        // 0:  6a 05                   push   0x5
        // 2:  c3                      ret
        // 3:  90                      nop
        // 4:  90                      nop
        // 5:  48 c7 c0 01 00 00 00    mov    rax,0x1
        emu_check(&b"\x6A\x05\xC3\x90\x90\x48\xC7\xC0\x01\x00\x00\x00"[..]);
    }

    #[test]
    fn fs_gs() -> Result<()> {
        // 32bit:
        // 0:  64 a1 30 00 00 00       mov    eax,fs:0x30
        let mut emu = emu_from_shellcode32(&b"\x64\xA1\x30\x00\x00\x00"[..]);
        emu.mem.mmap(0x7000, 0x1000, Permissions::RW).unwrap();
        emu.set_fsbase(0x7000);
        emu.mem.write_u32(0x7030, 0x1122_3344)?;
        emu.step()?;
        assert_eq!(emu.reg.eax(), 0x1122_3344);

        // 64bit:
        // 0:  65 48 8b 04 25 60 00 00 00   mov    rax,QWORD PTR gs:0x60
        let mut emu = emu_from_shellcode64(&b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"[..]);
        emu.mem.mmap(0x7000, 0x1000, Permissions::RW).unwrap();
        emu.set_gsbase(0x7000);
        emu.mem.write_u64(0x7060, 0x1122_3344_5566_7788)?;
        emu.step()?;
        assert_eq!(emu.reg.rax(), 0x1122_3344_5566_7788);

        Ok(())
    }
}
