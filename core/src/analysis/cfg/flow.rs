use anyhow::Result;
use smallvec::{smallvec, SmallVec};

use crate::{
    analysis::dis,
    module::{Module, Permissions},
    VA,
};

/// The type and destination of a control flow.
#[derive(Debug, Clone, Copy)]
pub enum Flow {
    // mov eax, eax
    // push ebp
    Fallthrough(VA),

    // call [0x401000]
    Call(VA),

    // call [eax]
    //IndirectCall { src: Rva },

    // jmp 0x401000
    UnconditionalJump(VA),

    // jmp eax
    //UnconditionalIndirectJump { src: Rva, dst: Rva },

    // jnz 0x401000
    ConditionalJump(VA),

    // jnz eax
    //ConditionalIndirectJump { src: Rva },

    // cmov 0x1
    ConditionalMove(VA),
}

impl Flow {
    pub fn va(&self) -> VA {
        match *self {
            Flow::Fallthrough(va) => va,
            Flow::Call(va) => va,
            Flow::UnconditionalJump(va) => va,
            Flow::ConditionalJump(va) => va,
            Flow::ConditionalMove(va) => va,
        }
    }

    /// create a new Flow with the va swapped out for the given va.
    /// useful when you have a flow edge that you want to reverse
    /// (e.g. from successor to predecessor).
    #[must_use]
    pub fn swap(&self, va: VA) -> Flow {
        match *self {
            Flow::Fallthrough(_) => Flow::Fallthrough(va),
            Flow::Call(_) => Flow::Call(va),
            Flow::UnconditionalJump(_) => Flow::UnconditionalJump(va),
            Flow::ConditionalJump(_) => Flow::ConditionalJump(va),
            Flow::ConditionalMove(_) => Flow::ConditionalMove(va),
        }
    }
}

/// most instructions have 1-2 flows, so attempt to store the inline.
pub type Flows = SmallVec<[Flow; 2]>;

fn is_executable(module: &Module, va: VA) -> bool {
    module.probe_va(va, Permissions::X)
}

pub fn get_call_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CALL, then its a programming error. panic!
    // all CALLs should have an operand.
    let op = dis::get_first_operand(insn).expect("CALL has no operand");

    if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
        if is_executable(module, dst) {
            return Ok(smallvec![Flow::Call(dst)]);
        }
    }
    Ok(smallvec![])
}

pub fn get_jmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a JMP, then its a programming error. panic!
    // all JMPs should have an operand.
    let op = dis::get_first_operand(insn).expect("JMP has no target");

    if op.ty == zydis::OperandType::MEMORY
        && op.mem.scale == 0x4
        && op.mem.base == zydis::Register::NONE
        && op.mem.disp.has_displacement
    {
        // this looks like a switch table, e.g. `JMP [0x1000+ecx*4]`
        // it should probably be solved via emulation.
        // see analysis/pe/pointers.rs for some experiments looking at pointer tables.
        Ok(smallvec![])
    } else {
        if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
            if is_executable(module, dst) {
                return Ok(smallvec![Flow::UnconditionalJump(dst)]);
            }
        }
        Ok(smallvec![])
    }
}

pub fn get_cjmp_insn_flow(module: &Module, va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    // if this is not a CJMP, then its a programming error. panic!
    // all conditional jumps should have an operand.
    let op = dis::get_first_operand(insn).expect("CJMP has no target");

    if let Ok(Some(dst)) = dis::get_operand_xref(module, va, insn, op) {
        if is_executable(module, dst) {
            return Ok(smallvec![Flow::ConditionalJump(dst)]);
        }
    }
    Ok(smallvec![])
}

pub fn get_cmov_insn_flow(va: VA, insn: &zydis::DecodedInstruction) -> Result<Flows> {
    let next = va + insn.length as u64;
    Ok(smallvec![Flow::ConditionalMove(next)])
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
        | zydis::Mnemonic::CMOVZ => get_cmov_insn_flow(va, insn)?,

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
        assert_eq!(flows[0].va(), 0x5);
    }

    #[test]
    fn test_get_jmp_insn_flow() {
        // E9 00 00 00 00  JMP $+5
        // 90              NOP
        let module = load_shellcode32(b"\xE9\x00\x00\x00\x00\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_jmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x5);
    }

    #[test]
    fn test_get_cjmp_insn_flow() {
        // 75 01 JNZ $+1
        // CC    BREAK
        // 90    NOP
        let module = load_shellcode32(b"\x75\x01\xCC\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_cjmp_insn_flow(&module, 0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x3);
    }

    #[test]
    fn test_get_cmov_insn_flow() {
        // 0F 44 C3  CMOVZ EAX, EBX
        // 90        NOP
        let module = load_shellcode32(b"\x0F\x44\xC3\x90");
        let insn = read_insn(&module, 0x0);
        let flows = get_cmov_insn_flow(0x0, &insn).unwrap();
        assert_eq!(flows[0].va(), 0x3);
    }
}
