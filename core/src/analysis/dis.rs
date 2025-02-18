use anyhow::Result;
use log::debug;

// because we use zydis data structures throughout our API
// make this dependency public.
// this way, our users can do `use lancelot::analysis::dis::zydis`
// and not have any version conflicts.
pub use zydis;

use crate::{
    arch::Arch,
    module::{Module, Permissions},
    util, VA,
};

pub fn get_disassembler(module: &Module) -> Result<zydis::Decoder> {
    let mut decoder = match module.arch {
        Arch::X64 => zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?,
        Arch::X32 => zydis::Decoder::new(zydis::MachineMode::LEGACY_32, zydis::AddressWidth::_32)?,
    };

    // modes described here: https://github.com/zyantific/zydis/blob/5af06d64432aaa3f6af3cd3e120eefa061b790ab/include/Zydis/Decoder.h#L55
    //
    // performance, captured empirically:
    //  - minimal mode - 8.7M instructions/second
    //  - full mode    - 4.5M instructions/second
    decoder.enable_mode(zydis::DecoderMode::MINIMAL, false)?;

    decoder.enable_mode(zydis::DecoderMode::KNC, false)?;
    decoder.enable_mode(zydis::DecoderMode::MPX, false)?;
    decoder.enable_mode(zydis::DecoderMode::CET, false)?;
    decoder.enable_mode(zydis::DecoderMode::LZCNT, false)?;
    decoder.enable_mode(zydis::DecoderMode::TZCNT, false)?;
    decoder.enable_mode(zydis::DecoderMode::WBNOINVD, false)?;
    decoder.enable_mode(zydis::DecoderMode::CLDEMOTE, false)?;

    Ok(decoder)
}

pub fn linear_disassemble<'a>(
    decoder: &'a zydis::Decoder,
    buf: &'a [u8],
) -> impl Iterator<Item = (usize, zydis::Result<Option<zydis::DecodedInstruction>>)> + 'a {
    let mut offset = 0usize;
    let iter = std::iter::from_fn(move || {
        if offset >= buf.len() {
            return None;
        }

        let insn_offset = offset;
        let insn_buf = &buf[insn_offset..];
        let insn = decoder.decode(insn_buf);

        if let Ok(Some(insn)) = &insn {
            // see discussion of linear vs thorough disassemble in this module doc for
            // call_targets. thorough is 4x more expensive, with limited
            // results.

            // linear disassembly:
            offset += insn.length as usize;

            // thorough disassembly:
            // offset += 1;
        } else {
            offset += 1;
        }

        Some((insn_offset, insn))
    });

    Box::new(iter)
}

pub fn is_control_flow_instruction(insn: &zydis::DecodedInstruction) -> bool {
    use zydis::Mnemonic;

    matches!(
        insn.mnemonic,
        Mnemonic::CALL
            | Mnemonic::RET
            | Mnemonic::IRET
            | Mnemonic::IRETD
            | Mnemonic::IRETQ
            | Mnemonic::JMP
            | Mnemonic::JB
            | Mnemonic::JBE
            | Mnemonic::JCXZ
            | Mnemonic::JECXZ
            | Mnemonic::JKNZD
            | Mnemonic::JKZD
            | Mnemonic::JL
            | Mnemonic::JLE
            | Mnemonic::JNB
            | Mnemonic::JNBE
            | Mnemonic::JNL
            | Mnemonic::JNLE
            | Mnemonic::JNO
            | Mnemonic::JNP
            | Mnemonic::JNS
            | Mnemonic::JNZ
            | Mnemonic::JO
            | Mnemonic::JP
            | Mnemonic::JRCXZ
            | Mnemonic::JS
            | Mnemonic::JZ
    )
}

/// Does the given instruction have a fallthrough flow?
pub fn does_insn_fallthrough(insn: &zydis::DecodedInstruction) -> bool {
    match insn.mnemonic {
        zydis::Mnemonic::JMP => false,
        zydis::Mnemonic::RET => false,
        zydis::Mnemonic::IRET => false,
        zydis::Mnemonic::IRETD => false,
        zydis::Mnemonic::IRETQ => false,
        // we consider an INT3 (breakpoint) to not flow through.
        // we rely on this to deal with non-ret functions, as some
        // compilers may insert a CC byte following the call.
        //
        // really, we'd want to do a real non-ret analysis.
        // but thats still a TODO.
        //
        // see aadtb.dll:0x180001940 for an example.
        zydis::Mnemonic::INT3 => false,
        zydis::Mnemonic::INT => {
            match insn.operands[0].imm.value {
                // handled by nt!KiFastFailDispatch on Win8+
                // see: https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/
                0x29 => false,

                // handled by nt!KiRaiseAssertion
                // see: http://www.osronline.com/article.cfm%5Earticle=474.htm
                0x2C => false,

                // probably indicates bad code,
                // but this hasn't be thoroughly vetted yet.
                _ => {
                    debug!("{:#x?}", insn);
                    true
                }
            }
        }
        // TODO: call may not fallthrough if function is noret.
        // will need another pass to clean this up.
        zydis::Mnemonic::CALL => true,
        _ => true,
    }
}

fn print_op(_op: &zydis::DecodedOperand) {
    /*
    if cfg!(feature = "dump_serde") {
        use serde_json;

        let s = serde_json::to_string(op).unwrap();
        println!("op: {}", s);
    } else {
    */
    println!("op: TODO(print_op)");
    //}
}

pub fn get_operands(insn: &zydis::DecodedInstruction) -> impl Iterator<Item = &zydis::DecodedOperand> + '_ {
    insn.operands
        .iter()
        // explicit operands are guaranteed to be first:
        // https://github.com/zyantific/zydis/blob/6a17c48576e1b016ce098c4bdbd001a1403b6a0a/include/Zydis/DecoderTypes.h#L1005-L1007
        .take_while(|op| op.visibility == zydis::OperandVisibility::EXPLICIT)
}

/// zydis supports implicit operands,
/// which we don't currently use in our analysis.
/// so, fetch the first explicit operand to an instruction.
pub fn get_first_operand(insn: &zydis::DecodedInstruction) -> Option<&zydis::DecodedOperand> {
    get_operands(insn).next()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    // if direct, the address of the destination.
    Direct(VA),
    // if indirect, the VA is the address of the pointer.
    // e.g. 0x401000 in call [0x401000]
    // this may very well be zero or other junk.
    // this value might be useful to lookup against:
    //   - imports
    //   - jump tables
    Indirect(VA),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Target::Direct(va) => write!(f, "Direct(0x{:x})", va),
            Target::Indirect(va) => write!(f, "Indirect(0x{:x})", va),
        }
    }
}

// for a memory operand, like `mov eax, [0x401000]`
// fetch the pointer, rather than the dest,
// so like `0x401000`.
#[allow(clippy::if_same_then_else)]
pub fn get_memory_operand_ptr(
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
    if op.mem.base == zydis::Register::NONE
        && op.mem.index == zydis::Register::NONE
        && op.mem.scale == 0
        && op.mem.disp.has_displacement
    {
        // the operand is a deref of a memory address.
        // for example: JMP [0x0]
        // this means: read the ptr from 0x0, and then jump to it.
        //
        // we'll have to make some assumptions here:
        //  - the ptr doesn't change (can detect via mem segment perms)
        //  - the ptr is fixed up (TODO)
        //
        // see doctest: [test simple memory ptr operand]()

        if op.mem.disp.displacement < 0 {
            Ok(None)
        } else {
            Ok(Some(op.mem.disp.displacement as VA))
        }
    } else if op.mem.base == zydis::Register::RIP
        // only valid on x64
        && op.mem.index == zydis::Register::NONE
        && op.mem.scale == 0
        && op.mem.disp.has_displacement
    {
        // this is RIP-relative addressing.
        // it works like a relative immediate,
        // that is: dst = *(rva + displacement + instruction len)

        match util::va_add_signed(va + insn.length as u64, op.mem.disp.displacement) {
            None => Ok(None),
            Some(ptr) => Ok(Some(ptr)),
        }
    } else if op.mem.base != zydis::Register::NONE {
        // this is something like `CALL [eax+4]`
        // can't resolve without emulation
        // TODO: add test
        Ok(None)
    } else if op.mem.scale > 0 {
        // this is something like `JMP [0x1000+eax*4]` (32-bit)
        Ok(None)
    } else {
        println!("{va:#x}: get mem op xref");
        print_op(op);
        panic!("not supported");
    }
}

// for a memory operand, like `mov eax, [0x401000]`
// fetch what the pointer points to,
// which is *not* `0x401000` in this example.
#[allow(clippy::if_same_then_else)]
pub fn get_memory_operand_xref(
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
    if let Some(ptr) = get_memory_operand_ptr(va, insn, op)? {
        let dst = match module.read_va_at_va(ptr) {
            Ok(dst) => dst,
            Err(_) => return Ok(None),
        };

        // must be mapped
        if module.probe_va(dst, Permissions::RWX) {
            // this is the happy path!
            Ok(Some(dst))
        } else {
            // invalid address
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub fn get_pointer_operand_xref(op: &zydis::DecodedOperand) -> Result<Option<VA>> {
    // ref: https://c9x.me/x86/html/file_module_x86_id_147.html
    //
    // > Far Jumps in Real-Address or Virtual-8086 Mode.
    // > When executing a far jump in real address or virtual-8086 mode,
    // > the processor jumps to the code segment and offset specified with the
    // > target operand. Here the target operand specifies an absolute far
    // > address either directly with a pointer (ptr16:16 or ptr16:32) or
    // > indirectly with a memory location (m16:16 or m16:32). With the
    // > pointer method, the segment and address of the called procedure is
    // > encoded in the instruction, using a 4-byte (16-bit operand size) or
    // > 6-byte (32-bit operand size) far address immediate.
    // TODO: do something intelligent with the segment.
    Ok(Some(op.ptr.offset as u64))
}

pub fn get_immediate_operand_xref(
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<VA>> {
    if op.imm.is_relative {
        // the operand is an immediate constant relative to $PC.
        // destination = $pc + immediate + insn.len
        //
        // see doctest: [test relative immediate operand]()
        //
        // however, we can rely on zydis to do this calculation for us.
        // specifically for IMM operands with relative addressing.

        if let Ok(dst) = insn.calc_absolute_address(va, op) {
            // must be mapped
            if module.probe_va(dst, Permissions::RWX) {
                Ok(Some(dst))
            } else {
                // invalid address
                Ok(None)
            }
        } else {
            Ok(None)
        }
    } else {
        // the operand is an immediate absolute address.

        let dst = if op.imm.is_signed {
            let imm = util::u64_i64(op.imm.value);
            if imm < 0 {
                // obviously this isn't an address if negative.
                return Ok(None);
            }
            imm as u64
        } else {
            op.imm.value
        };

        // must be mapped
        if module.probe_va(dst, Permissions::RWX) {
            Ok(Some(dst))
        } else {
            // invalid address
            Ok(None)
        }
    }
}

pub fn get_operand_xref(
    module: &Module,
    va: VA,
    insn: &zydis::DecodedInstruction,
    op: &zydis::DecodedOperand,
) -> Result<Option<Target>> {
    match op.ty {
        // like: .text:0000000180001041 FF 15 D1 78 07 00      call    cs:__imp_RtlVirtualUnwind_0
        //           0x0000000000001041:                       call    [0x0000000000079980]
        zydis::OperandType::MEMORY => match get_memory_operand_ptr(va, insn, op) {
            Ok(Some(ptr)) => Ok(Some(Target::Indirect(ptr))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        },

        // like: EA 33 D2 B9 60 80 40  jmp  far ptr 4080h:60B9D233h
        // "ptr": {
        //    "segment": 16512,
        //    "offset": 1622790707
        // },
        zydis::OperandType::POINTER => match get_pointer_operand_xref(op) {
            Ok(Some(ptr)) => Ok(Some(Target::Indirect(ptr))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        },

        zydis::OperandType::IMMEDIATE => match get_immediate_operand_xref(module, va, insn, op) {
            Ok(Some(va)) => Ok(Some(Target::Direct(va))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        },

        // like: CALL [rax]
        // which cannot be resolved without emulation.
        zydis::OperandType::REGISTER => Ok(Some(Target::Indirect(0x0))),

        zydis::OperandType::UNUSED => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use crate::{analysis::dis::*, rsrc::*, test::*};
    use std::ops::Not;

    #[test]
    fn test_get_memory_operand_ptr() {
        //```
        // .text:00000001800134D4 call    cs:KernelBaseGetGlobalData
        //```
        //
        // this should result in a call flow to IAT entry 0x1800773F0
        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf).unwrap();

        let insn = read_insn(&pe.module, 0x1800134D4);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_memory_operand_ptr(0x1800134D4, &insn, op).unwrap();

        assert!(xref.is_some());
        assert_eq!(xref.unwrap(), 0x1800773F0);
    }

    #[test]
    fn test_get_memory_operand_xref_simple() {
        // 0:  ff 25 06 00 00 00   +->  jmp    DWORD PTR ds:0x6
        // 6:  00 00 00 00         +--  dw     0x0
        let module = load_shellcode32(b"\xFF\x25\x06\x00\x00\x00\x00\x00\x00\x00");
        let insn = read_insn(&module, 0x0);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_memory_operand_xref(&module, 0x0, &insn, op).unwrap();

        assert!(xref.is_some());
        assert_eq!(xref.unwrap(), 0x0);
    }

    #[test]
    fn test_get_memory_operand_xref_rip_relative() {
        // FF 15 00 00 00 00         CALL $+5
        // 00 00 00 00 00 00 00 00   dq 0x0
        let module = load_shellcode64(b"\xFF\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let insn = read_insn(&module, 0x0);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_memory_operand_xref(&module, 0x0, &insn, op).unwrap();

        assert!(xref.is_some());
        assert_eq!(xref.unwrap(), 0x0);
    }

    #[test]
    fn test_get_pointer_operand_xref() {
        // this is a far ptr jump from addr 0x0 to itmodule:
        // JMP FAR PTR 0:00000000
        // [ EA ] [ 00 00 00 00 ] [ 00 00 ]
        // opcode   ptr            segment
        let module = load_shellcode32(b"\xEA\x00\x00\x00\x00\x00\x00");
        let insn = read_insn(&module, 0x0);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_pointer_operand_xref(op).unwrap();

        assert!(xref.is_some(), "has pointer operand xref");
        assert_eq!(xref.unwrap(), 0x0, "correct pointer operand xref");
    }

    #[test]
    fn test_get_immediate_operand_xref() {
        // this is a jump from addr 0x0 to itmodule:
        // JMP $+0;
        let module = load_shellcode32(b"\xEB\xFE");
        let insn = read_insn(&module, 0x0);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_immediate_operand_xref(&module, 0x0, &insn, op).unwrap();

        assert!(xref.is_some(), "has immediate operand");
        assert_eq!(xref.unwrap(), 0x0, "correct immediate operand");

        // this is a jump from addr 0x0 to -1, which is unmapped
        // JMP $-1;
        let module = load_shellcode32(b"\xEB\xFD");
        let insn = read_insn(&module, 0x0);
        let op = get_first_operand(&insn).unwrap();
        let xref = get_immediate_operand_xref(&module, 0x0, &insn, op).unwrap();

        assert!(xref.is_some().not(), "does not have immediate operand");
    }

    #[test]
    fn test_format_insn() {
        use crate::analysis::dis::zydis;

        let buf = get_buf(Rsrc::K32);
        let pe = crate::loader::pe::PE::from_bytes(&buf).unwrap();

        let mut formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();

        struct UserData {
            names:                  std::collections::BTreeMap<VA, String>,
            orig_print_address_abs: Option<zydis::Hook>,
        }

        let mut userdata = Box::new(UserData {
            names:                  Default::default(),
            orig_print_address_abs: None,
        });

        let orig = formatter
            .set_print_address_abs(Box::new(
                |formatter: &zydis::Formatter,
                 buf: &mut zydis::FormatterBuffer,
                 ctx: &mut zydis::FormatterContext,
                 userdata: Option<&mut dyn core::any::Any>|
                 -> zydis::Result<()> {
                    // programming error: userdata must be provided.
                    // TODO: enforce via types.
                    let userdata = userdata.expect("no userdata");

                    // programming error: userdata must be a Box<UserData>.
                    // TODO: enforce via types.
                    let userdata = userdata.downcast_ref::<Box<UserData>>().expect("incorrect userdata");

                    let absolute_address = unsafe {
                        // safety: the insn and operands come from zydis, so we assume they contain
                        // valid data.
                        let insn: &zydis::DecodedInstruction = &*ctx.instruction;
                        let op: &zydis::DecodedOperand = &*ctx.operand;
                        insn.calc_absolute_address(ctx.runtime_address, op)
                            .expect("failed to calculate absolute address")
                    };

                    #[allow(clippy::needless_return)]
                    if let Some(name) = userdata.names.get(&absolute_address) {
                        // name is found in map, use that.
                        return buf.get_string()?.append(name);
                    } else {
                        // name is not found, use original formatter.

                        // programming error: the original hook must be recorded.
                        // TODO: enforce via types.
                        let orig = userdata.orig_print_address_abs.as_ref().expect("no original hook");

                        if let zydis::Hook::PrintAddressAbs(Some(f)) = orig {
                            // safety: zydis::Formatter <-> zydis::ffi::ZydisFormatter is safe according to
                            // here: https://docs.rs/zydis/3.1.2/src/zydis/formatter.rs.html#306
                            let status =
                                unsafe { f(formatter as *const _ as *const zydis::ffi::ZydisFormatter, buf, ctx) };
                            if status.is_error() {
                                return Err(status);
                            } else {
                                return Ok(());
                            }
                        } else {
                            // I'm not sure how this could ever be the case, as zydis initializes the hook
                            // with a default. I suppose if you explicitly set
                            // the callback to NULL/None? Which we don't do here.
                            panic!("unexpected original hook");
                        }
                    }
                },
            ))
            .unwrap();
        userdata.orig_print_address_abs = Some(orig);

        // format a global address (KernelBaseGetGlobalData).
        //
        // call to KernelBaseGetGlobalData:
        // ```
        //     .text:00000001800134D0 48 83 EC 48        sub    rsp, 48h
        //     .text:00000001800134D4 FF 15 16 3F 06 00  call   cs:KernelBaseGetGlobalData  ; .idata:00000001800773F0
        //     .text:00000001800134DA 0F 10 50 40        movups xmm2, xmmword ptr [rax+40h]
        // ```
        userdata
            .names
            .insert(0x1800773F0, String::from("KernelBaseGetGlobalData"));
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        let insn = read_insn(&pe.module, 0x1800134D4);
        formatter
            .format_instruction(&insn, &mut buffer, Some(0x1800134D4), Some(&mut userdata))
            .unwrap();
        assert_eq!(buffer.as_str().unwrap(), "call [KernelBaseGetGlobalData]");

        // but fall-back to the original formatter if symbol is not present.
        //
        // call to BaseFormatObjectAttributes:
        // ```
        //     .text:000000018001995E 45 33 C0           xor  r8d, r8d
        //     .text:0000000180019961 FF 15 D1 D7 05 00  call cs:BaseFormatObjectAttributes_0  ; .idata:0000000180077138
        //     .text:0000000180019967 85 C0              test eax, eax
        // ```
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        let insn = read_insn(&pe.module, 0x180019961);
        formatter
            .format_instruction(&insn, &mut buffer, Some(0x180019961), Some(&mut userdata))
            .unwrap();
        assert_eq!(buffer.as_str().unwrap(), "call [0x0000000180077138]");
    }
}
