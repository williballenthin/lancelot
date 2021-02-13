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
pub mod reg;

#[derive(Error, Debug)]
pub enum EmuError {
    #[error("invalid instruction: {0:#x}")]
    InvalidInstruction(VA),
}

#[derive(Clone)]
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

    pub fn from_module(m: &Module) -> Emulator {
        let mut emu = Emulator::with_arch(m.arch);

        for section in m.sections.iter() {
            let mut page_addr = section.virtual_range.start;

            let section_size = section.virtual_range.end - section.virtual_range.start;
            emu.mem
                .mmap(
                    section.virtual_range.start,
                    crate::util::align(section_size, mmu::PAGE_SIZE as u64),
                    Permissions::W,
                )
                .unwrap();

            while page_addr < section.virtual_range.end {
                let mut page = [0u8; mmu::PAGE_SIZE];

                // AddressSpace currently allows non-page-aligned sizes.
                let page_data = if page_addr + mmu::PAGE_SIZE as u64 > section.virtual_range.end {
                    &mut page[..(section.virtual_range.end - page_addr) as usize]
                } else {
                    &mut page[..]
                };

                m.address_space.read_into(page_addr, page_data).unwrap();
                emu.mem.write_page(page_addr, &page[..]).unwrap();
                page_addr += mmu::PAGE_SIZE as u64;
            }

            emu.mem
                .mprotect(
                    section.virtual_range.start,
                    crate::util::align(section_size, mmu::PAGE_SIZE as u64),
                    section.permissions,
                )
                .unwrap();
        }

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

    pub fn fetch(&mut self) -> Result<zydis::DecodedInstruction> {
        // TODO: 32 vs 64
        let pc = self.reg.rip;
        debug!("emu: fetch: {:#x}", pc);

        // TODO: segmentation.

        let mut buf = [0u8; 16];

        // TODO: perms for read should be X, not R.
        self.mem.read(pc, &mut buf[..])?;
        // TODO: if fail, callback.

        let insn = self.dis.decode(&buf[..]);

        if let Ok(Some(insn)) = insn {
            Ok(insn)
        } else {
            Err(EmuError::InvalidInstruction(pc).into())
        }
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
                addr -= op.mem.disp.displacement as u64;
            } else {
                addr += op.mem.disp.displacement as u64;
            }
        }

        addr
    }

    fn read_memory(&self, src: &DecodedOperand) -> Result<u64> {
        let addr = self.get_operand_address(src);

        match src.size {
            64 => self.mem.read_u64(addr),
            32 => self.mem.read_u32(addr).map(|v| v as u64),
            16 => self.mem.read_u16(addr).map(|v| v as u64),
            8 => self.mem.read_u8(addr).map(|v| v as u64),
            s => unimplemented!("memory read size: {:?}", s),
        }
    }

    fn write_memory(&mut self, dst: &DecodedOperand, value: u64) -> Result<()> {
        let addr = self.get_operand_address(dst);

        match dst.size {
            64 => self.mem.write_u64(addr, value),
            32 => self.mem.write_u32(addr, value as u32),
            16 => self.mem.write_u16(addr, value as u16),
            8 => self.mem.write_u8(addr, value as u8),
            s => unimplemented!("memory write size: {:?}", s),
        }
    }

    fn read_operand(&mut self, insn: &DecodedInstruction, src: &DecodedOperand) -> Result<u64> {
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
            MEMORY => self.read_memory(&src)?,
            t => unimplemented!("read operand type: {:?}", t),
        })
    }

    fn write_operand(&mut self, dst: &DecodedOperand, value: u64) -> Result<()> {
        use zydis::enums::OperandType::*;

        match dst.ty {
            REGISTER => self.write_register(dst.reg, value),
            // handle unmapped write
            MEMORY => self.write_memory(&dst, value)?,
            t => unimplemented!("write operand type: {:?}", t),
        }

        Ok(())
    }

    pub fn step(&mut self) -> Result<()> {
        use zydis::enums::{Mnemonic::*, Register::*};

        debug!("emu: step: {:#x}", self.reg.rip);
        let insn = self.fetch()?;
        // TODO: handle invalid fetch
        // TODO: handle invalid instruction

        debug!("emu: insn: {:#x}: {:#?}", self.reg.rip, insn.mnemonic);
        match insn.mnemonic {
            // TODO:
            //  - sub/add
            //  - cmp
            //  - jz/jnz
            MOV => {
                //println!("{:#?}", insn);

                let dst = &insn.operands[0];
                let src = &insn.operands[1];

                let value = self.read_operand(&insn, src)?;
                self.write_operand(dst, value)?;

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
                // EXPLICIT/READ/IMMEDIATE|REGISTER
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
                let value = self.read_operand(&insn, src)?;

                match sp_op.reg {
                    RSP => self.reg.rsp -= 8,
                    ESP => self.reg.rsp -= 4,
                    _ => unimplemented!(),
                }

                self.write_operand(&dst, value)?;

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

                let value = self.read_operand(&insn, src)?;

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

                self.write_operand(&dst, value)?;

                self.reg.rip += insn.length as u64;
            }

            CALL => {
                // EXPLICIT/READ/MEMORY|REGISTER call target
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

                let target_addr = self.read_operand(&insn, target)?;
                self.write_operand(pc, target_addr)?;
            }

            SUB => {
                println!("{:#?}", insn);
                unimplemented!("sub");
                /*
                // EXPLICIT/READ|WRITE
                let dst = &insn.operands[0];
                // EXPLICIT/READ
                let src = &insn.operands[1];
                // EXPLICIT/WRITE/RFLAGS
                let flags = &insn.operands[2];
                assert!(flags.ty == zydis::enums::OperandType::REGISTER);

                let m = self.read_operand(&insn, dst)?;
                let n = self.read_operand(&insn, src)?;

                // http://service.scs.carleton.ca/sivarama/asm_book_web/Student_copies/ch6_arithmetic.pdf
                // cf - result of an arithmetic operation on unsigned numbers is out of range.
                // of - out-of-range result on signed numbers.
                // sf - sign of the result. Simply a copy of the most significant bit of the result.
                // af - operation produced a carry or borrow in the low-order 4 bits (nibble) of 8-, 16-, or 32-bit operands.
                //      No conditional jump instructions with this flag.
                // pf - Indicates even parity of the low 8 bits of the result.
                //      PF is set if the lower 8 bits contain even number 1 bits.
                let (o, sf) = match dst.size {
                    64 => {
                        let o = m.wrapping_sub(n);
                        let sf = (o & (1 << 31)) > 0;
                        (o, sf)
                    },
                    32 => {
                        // TODO: need to do sign extension, e.g. if n is u16
                        let o = (m as u32).wrapping_sub(n as u32) as u64;
                        let sf = (o & (1 << 31)) > 0;
                        (o, sf)
                    },
                    16 => {
                        let o = (m as u16).wrapping_sub(n as u16) as u64;
                        let sf = (o & (1 << 15)) > 0;
                        (o, sf)
                    },
                    8 => {
                        let o = (m as u8).wrapping_sub(n as u8) as u64;
                        let sf = (o & (1 << 7)) > 0;
                        (o, sf)
                    },
                    s => unimplemented!("sub size {:}", s),
                };

                let of = n > m;
                let zf = o == 0;
                */
            }

            m => {
                unimplemented!("mnemonic: {:?}", m);
                //self.reg.rip += insn.length as u64;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{arch::Arch, emu::*, rsrc::*, test::*};

    use anyhow::Result;

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
        assert_eq!(emu.reg.rax(), 0xFFFF_FFFF_0000_0001);

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
            // do nothing
        }));

        // catch expected panic
        // ref: https://stackoverflow.com/a/42649833/87207
        assert!(
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

    fn emu_check(code: &[u8], steps: u32) {
        let mut uc = uc::uc_from_shellcode64(code);
        let mut emu = emu_from_shellcode64(code);

        for _ in 0..steps {
            uc.step().unwrap();
            emu.step().unwrap();
            uc.check(&emu)
        }
    }

    #[test]
    fn test_uc_check() {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        emu_check(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..], 1);
    }

    #[test]
    fn insn_mov() -> Result<()> {
        // 0:  48 c7 c0 01 00 00 00    mov    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\xC7\xC0\x01\x00\x00\x00"[..]);
        emu.step()?;
        assert_eq!(emu.reg.rax, 1);

        // 0:  48 89 c3                mov    rbx,rax
        let mut emu = emu_from_shellcode64(&b"\x48\x89\xC3"[..]);
        emu.reg.rax = 1;
        emu.step()?;

        assert_eq!(emu.reg.rax, 1);
        assert_eq!(emu.reg.rbx, 1);

        Ok(())
    }

    #[test]
    fn insn_lea() -> Result<()> {
        // 0:  48 8d 58 04             lea    rbx,[rax+0x4]
        let mut emu = emu_from_shellcode64(&b"\x48\x8D\x58\x04"[..]);
        emu.reg.rax = 0x80;
        emu.step()?;
        assert_eq!(emu.reg.rbx, 0x84);

        Ok(())
    }

    #[test]
    fn insn_sub() -> Result<()> {
        /*
        // 0:  48 83 e8 01             sub    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\x83\xE8\x01"[..]);
        emu.reg.rax = 0x1;
        emu.step()?;
        assert_eq!(emu.reg.rax, 0x0);
        assert!(emu.reg.zf());

        // 0:  48 83 e8 01             sub    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\x83\xE8\x01"[..]);
        emu.reg.rax = 0x2;
        emu.step()?;
        assert_eq!(emu.reg.rax, 0x1);
        assert!(!emu.reg.zf());

        // 0:  48 83 e8 01             sub    rax,0x1
        let mut emu = emu_from_shellcode64(&b"\x48\x83\xE8\x01"[..]);
        emu.reg.rax = 0x0;
        emu.step()?;
        assert_eq!(emu.reg.rax, 0xFFFF_FFFF_FFFF_FFFF);
        assert!(!emu.reg.zf());
        */

        Ok(())
    }

    #[test]
    fn insn_push_pop() -> Result<()> {
        // 0:  6a 01                   push   0x1
        let mut emu = emu_from_shellcode64(&b"\x6A\x01"[..]);
        emu.step()?;
        assert_eq!(emu.mem.read_u64(emu.reg.rsp())?, 1);

        // 0:  6a 01                   push   0x1
        // 2:  58                      pop    rax
        let mut emu = emu_from_shellcode64(&b"\x6A\x01\x58"[..]);
        emu.step()?;
        emu.step()?;
        assert_eq!(emu.reg.rax, 1);

        Ok(())
    }

    #[test]
    fn insn_call() -> Result<()> {
        // 0:  e8 00 00 00 00          call   $+5
        let mut emu = emu_from_shellcode64(&b"\xE8\x00\x00\x00\x00"[..]);
        emu.step()?;
        assert_eq!(emu.reg.rip, 0x5);

        // 0:  ff d0                   call   rax
        let mut emu = emu_from_shellcode64(&b"\xFF\xD0"[..]);
        emu.reg.rax = 0x80;
        emu.step()?;
        assert_eq!(emu.reg.rip, 0x80);

        // 0x00:  ff 14 25 40 00 00 00    call   QWORD PTR ds:0x40
        // 0x40:  0x0000000000000080
        let mut emu = emu_from_shellcode64(&b"\xFF\x14\x25\x40\x00\x00\x00"[..]);
        emu.mem.write_u64(0x40, 0x80)?;
        emu.step()?;
        assert_eq!(emu.reg.rip, 0x80);

        // 0x00:  ff 50 08                call   QWORD PTR [rax+0x8]
        // 0x40:  0x0000000000000070
        // 0x48:  0x0000000000000080
        let mut emu = emu_from_shellcode64(&b"\xFF\x50\x08"[..]);
        emu.reg.rax = 0x40;
        emu.mem.write_u64(0x40, 0x70)?;
        emu.mem.write_u64(0x48, 0x80)?;
        emu.step()?;
        assert_eq!(emu.reg.rip, 0x80);

        Ok(())
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

    #[test]
    fn nop() -> Result<()> {
        //init_logging();

        let buf = get_buf(Rsrc::NOP);
        let pe = crate::loader::pe::PE::from_bytes(&buf)?;
        let mut emu = Emulator::from_module(&pe.module);

        let opt = pe.header.optional_header.unwrap();
        let ep = opt.windows_fields.image_base + opt.standard_fields.address_of_entry_point;
        emu.reg.rip = ep;

        emu.mem.mmap(0x5000, 0x2000, Permissions::RW).unwrap();
        emu.reg.rsp = 0x6000;
        emu.reg.rbp = 0x6000;

        emu.mem.mmap(0x7000, 0x1000, Permissions::RW).unwrap();
        emu.set_fsbase(0x7000);

        // .text:00401081 push    18h
        // .text:00401083 push    offset stru_406160
        // .text:00401088 call    __SEH_prolog
        assert_eq!(emu.reg.rip, 0x401081);
        emu.step()?; // push
        emu.step()?; // push
        emu.step()?; // call

        // .text:004027A0 __SEH_prolog proc near
        // .text:004027A0 push    offset __except_handler3
        // .text:004027A5 mov     eax, large fs:0
        // .text:004027AB push    eax
        // .text:004027AC mov     eax, [esp+8+arg_4]
        // .text:004027B0 mov     [esp+8+arg_4], ebp
        // .text:004027B4 lea     ebp, [esp+8+arg_4]
        // .text:004027B8 sub     esp, eax
        assert_eq!(emu.reg.rip, 0x4027A0);
        emu.step()?; // push
        emu.step()?; // mov
        emu.step()?; // push
        emu.step()?; // mov
        emu.step()?; // mov
        emu.step()?; // lea
                     //emu.step()?; // sub

        Ok(())
    }
}
