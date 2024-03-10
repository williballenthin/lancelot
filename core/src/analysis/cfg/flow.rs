use anyhow::Result;
use smallvec::{smallvec, SmallVec};

use crate::{
    analysis::dis::{self, Target},
    aspace::AddressSpace,
    module::{Module, Permissions},
    VA,
};

/// The type and destination of a control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    // mov eax, eax
    // push ebp
    // TODO: consider moving this single bit into the insn descriptor for a memory savings of 63 bits?
    Fallthrough(VA),

    // call $+5
    // call [0x401000]
    Call(Target),

    // jmp 0x401000
    // jmp [table + eax*4]
    UnconditionalJump(Target),

    // in x86, all conditional jumps are direct.
    // jnz 0x401000
    //
    // there are no conditional indirect jumps,
    // https://www.felixcloutier.com/x86/jmp
    // https://www.felixcloutier.com/x86/jcc
    ConditionalJump(VA),
}

impl Flow {
    /// create a new Flow with the va swapped out for the given va.
    /// useful when you have a flow edge that you want to reverse
    /// (e.g. from successor to predecessor).
    #[must_use]
    pub fn swap(&self, va: VA) -> Flow {
        match *self {
            Flow::Fallthrough(_) => Flow::Fallthrough(va),
            Flow::Call(Target::Direct(_)) => Flow::Call(Target::Direct(va)),
            Flow::Call(Target::Indirect(_)) => Flow::Call(Target::Indirect(va)),
            Flow::UnconditionalJump(Target::Direct(_)) => Flow::UnconditionalJump(Target::Direct(va)),
            Flow::UnconditionalJump(Target::Indirect(_)) => Flow::UnconditionalJump(Target::Indirect(va)),
            Flow::ConditionalJump(_) => Flow::ConditionalJump(va),
        }
    }
}

/// most instructions have 1-2 flows, so attempt to store the inline.
pub type Flows = SmallVec<[Flow; 2]>;

fn is_executable(module: &Module, va: VA) -> bool {
    module.probe_va(va, Permissions::X)
}

/// Is the given address a NULL byte (which is not a relevant x86 instruction).
/// If the address isn't mapped, return false.
fn is_empty(module: &Module, va: VA) -> bool {
    match module.address_space.read_u8(va) {
        Ok(0) => true,
        Ok(_) => false,
        Err(_) => false,
    }
}

pub fn get_call_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CALL, then its a programming error. panic!
    // all CALLs should have an operand.
    let op = dis::get_first_operand(insn).expect("CALL has no operand");

    if let Ok(Some(target)) = dis::get_operand_xref(module, va, insn, op) {
        match target {
            Target::Direct(va) => {
                if !is_executable(module, va) {
                    // direct call to a non-executable part of the file,
                    // which doesn't make sense.
                    return Ok(smallvec![]);
                }

                if !module.is_in_image(va) {
                    // region doesn't exist on disk,
                    // like the RWX region that UPX unpacks to.
                    // physical size=0, virtual size=big.
                    return Ok(smallvec![]);
                }

                if is_empty(module, va) {
                    // region exists on disk, but it starts with a NULL byte,
                    // which isn't a reasonable x86 instruction.
                    return Ok(smallvec![]);
                }

                return Ok(smallvec![Flow::Call(target)]);
            }
            Target::Indirect(_) => {
                // indirect call ptr can be in non-executable region,
                // such as the import table.
                return Ok(smallvec![Flow::Call(target)]);
            }
        }
    }
    Ok(smallvec![])
}

pub fn get_jmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a JMP, then its a programming error. panic!
    // all JMPs should have an operand.
    let op = dis::get_first_operand(insn).expect("JMP has no target");

    if let Ok(Some(target)) = dis::get_operand_xref(module, va, insn, op) {
        match target {
            Target::Direct(va) => {
                if !is_executable(module, va) {
                    // direct jump to a non-executable part of the file,
                    // which doesn't make sense.
                    return Ok(smallvec![]);
                }

                if !module.is_in_image(va) {
                    // region doesn't exist on disk,
                    // like the RWX region that UPX unpacks to.
                    // physical size=0, virtual size=big.
                    return Ok(smallvec![]);
                }

                if is_empty(module, va) {
                    // region exists on disk, but it starts with a NULL byte,
                    // which isn't a reasonable x86 instruction.
                    return Ok(smallvec![]);
                }

                return Ok(smallvec![Flow::UnconditionalJump(target)]);
            }
            Target::Indirect(_) => {
                // indirect jmp ptr can be in non-executable region,
                // such as switch table.
                return Ok(smallvec![Flow::UnconditionalJump(target)]);
            }
        }
    }
    Ok(smallvec![])
}

pub fn get_cjmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CJMP, then its a programming error. panic!
    // all conditional jumps should have an operand.
    let op = dis::get_first_operand(insn).expect("CJMP has no target");

    if let Ok(Some(Target::Direct(dst))) = dis::get_operand_xref(module, va, insn, op) {
        if !is_executable(module, dst) {
            // conditional jump to a non-executable part of the file,
            // which doesn't make sense.
            return Ok(smallvec![]);
        }

        if !module.is_in_image(dst) {
            // region doesn't exist on disk,
            // like the RWX region that UPX unpacks to.
            // physical size=0, virtual size=big.
            return Ok(smallvec![]);
        }

        if is_empty(module, va) {
            // region exists on disk, but it starts with a NULL byte,
            // which isn't a reasonable x86 instruction.
            return Ok(smallvec![]);
        }

        return Ok(smallvec![Flow::ConditionalJump(dst)]);
    }
    Ok(smallvec![])
}

pub fn get_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    let mut flows = match insn.mnemonic {
        zydis::Mnemonic::CALL => get_call_insn_flow(module, va, insn)?,

        zydis::Mnemonic::JMP => get_jmp_insn_flow(module, va, insn)?,

        zydis::Mnemonic::RET | zydis::Mnemonic::IRET | zydis::Mnemonic::IRETD | zydis::Mnemonic::IRETQ => smallvec![],

        zydis::Mnemonic::JB
        | zydis::Mnemonic::JBE
        | zydis::Mnemonic::JCXZ
        | zydis::Mnemonic::JECXZ
        | zydis::Mnemonic::JKNZD
        | zydis::Mnemonic::JKZD
        | zydis::Mnemonic::JL
        | zydis::Mnemonic::JLE
        | zydis::Mnemonic::JNB
        | zydis::Mnemonic::JNBE
        | zydis::Mnemonic::JNL
        | zydis::Mnemonic::JNLE
        | zydis::Mnemonic::JNO
        | zydis::Mnemonic::JNP
        | zydis::Mnemonic::JNS
        | zydis::Mnemonic::JNZ
        | zydis::Mnemonic::JO
        | zydis::Mnemonic::JP
        | zydis::Mnemonic::JRCXZ
        | zydis::Mnemonic::JS
        | zydis::Mnemonic::JZ => get_cjmp_insn_flow(module, va, insn)?,

        zydis::Mnemonic::CMOVB
        | zydis::Mnemonic::CMOVBE
        | zydis::Mnemonic::CMOVL
        | zydis::Mnemonic::CMOVLE
        | zydis::Mnemonic::CMOVNB
        | zydis::Mnemonic::CMOVNBE
        | zydis::Mnemonic::CMOVNL
        | zydis::Mnemonic::CMOVNLE
        | zydis::Mnemonic::CMOVNO
        | zydis::Mnemonic::CMOVNP
        | zydis::Mnemonic::CMOVNS
        | zydis::Mnemonic::CMOVNZ
        | zydis::Mnemonic::CMOVO
        | zydis::Mnemonic::CMOVP
        | zydis::Mnemonic::CMOVS
        | zydis::Mnemonic::CMOVZ => smallvec![],

        // TODO: syscall, sysexit, sysret, vmcall, vmmcall
        _ => smallvec![],
    };

    if dis::does_insn_fallthrough(insn) {
        flows.push(Flow::Fallthrough(va + insn.length as u64))
    }

    Ok(flows)
}

#[cfg(test)]
mod tests {
    use crate::{analysis::cfg::flow::*, test::*};

    #[test]
    fn test_get_call_insn_flow() {
        // E8 00 00 00 00  CALL $+5
        // 90              NOP
        let module = load_shellcode32(b"\xE8\x00\x00\x00\x00\x90");
        let insn = read_insn(&module, 0x0);

        let flows = get_call_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0], Flow::Call(Target::Direct(0x5)));

        let flows = get_insn_flow(&module, 0x0, &insn).unwrap();
        // two flows: call and fallthrough
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0], Flow::Call(Target::Direct(0x5)));
        assert_eq!(flows[1], Flow::Fallthrough(0x5));
    }

    #[test]
    fn test_get_jmp_insn_flow() {
        // E9 00 00 00 00  JMP $+5
        // 90              NOP
        let module = load_shellcode32(b"\xE9\x00\x00\x00\x00\x90");
        let insn = read_insn(&module, 0x0);

        let flows = get_jmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0], Flow::UnconditionalJump(Target::Direct(0x5)));

        let flows = get_insn_flow(&module, 0x0, &insn).unwrap();
        // one flow: jmp
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0], Flow::UnconditionalJump(Target::Direct(0x5)));
    }

    #[test]
    fn test_get_cjmp_insn_flow() {
        // 75 01 JNZ $+3
        // CC    BREAK
        // 90    NOP
        let module = load_shellcode32(b"\x75\x01\xCC\x90");
        let insn = read_insn(&module, 0x0);

        let flows = get_cjmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0], Flow::ConditionalJump(0x3));

        let flows = get_insn_flow(&module, 0x0, &insn).unwrap();
        // two flows: fallthrough and conditional jump
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0], Flow::ConditionalJump(0x3));
        assert_eq!(flows[1], Flow::Fallthrough(0x2));
    }

    #[test]
    fn test_get_cmov_insn_flow() {
        // 0F 44 C3  CMOVZ EAX, EBX
        // 90        NOP
        let module = load_shellcode32(b"\x0F\x44\xC3\x90");
        let insn = read_insn(&module, 0x0);

        let flows = get_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0], Flow::Fallthrough(0x3));
    }
}
