// TODO: consider renaming to "disassembler"
package disassembly

import (
	"errors"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"

	// we don't want to import this. seems like the dependency is backwards.
	// but, need this for ARCH_* constants, until they're separate.
	W "github.com/williballenthin/Lancelot/workspace"
)

const MAX_INSN_SIZE = 0x10

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var ErrFailedToDisassembleInstruction = errors.New("Failed to disassemble an instruction")

func New(ws *W.Workspace) (*gapstone.Engine, error) {
	if ws.Arch != W.ARCH_X86 {
		return nil, W.InvalidArchError
	}
	if !(ws.Mode == W.MODE_32 || ws.Mode == W.MODE_64) {
		return nil, W.InvalidModeError
	}

	disassembler, e := gapstone.New(
		W.GAPSTONE_ARCH_MAP[ws.Arch],
		W.GAPSTONE_MODE_MAP[ws.Mode],
	)
	if e != nil {
		return nil, e
	}
	e = disassembler.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	check(e)
	if e != nil {
		return nil, e
	}

	return &disassembler, nil
}

// ReadInstruction fetches bytes from the provided address space at the given
//  address and parses them into a single instruction instance.
func ReadInstruction(dis *gapstone.Engine, as AS.AddressSpace, va AS.VA) (gapstone.Instruction, error) {
	d, e := as.MemRead(va, uint64(MAX_INSN_SIZE))
	check(e)
	if e != nil {
		return gapstone.Instruction{}, AS.ErrInvalidMemoryRead
	}

	insns, e := dis.Disasm(d, uint64(va), 1)
	check(e)
	if e != nil {
		return gapstone.Instruction{}, ErrFailedToDisassembleInstruction
	}

	if len(insns) == 0 {
		return gapstone.Instruction{}, ErrFailedToDisassembleInstruction
	}

	insn := insns[0]
	return insn, nil
}

func DoesInstructionHaveGroup(i gapstone.Instruction, group uint) bool {
	for _, g := range i.Groups {
		if group == g {
			return true
		}
	}
	return false
}

// ErrFailedToResolveJumpTarget is an error to be returned when the target
//  of a jump cannot be computed.
// For example, in an indirect jump, during non-emulation-based analysis.
var ErrFailedToResolveJumpTarget = errors.New("Failed to resolve jump target")

// GetJumpTarget gets the address to which a known jump instruction
//  transfers control.
// If the instruction is a conditional jump, then this function returns
//  the "jump is taken" target.
func GetJumpTarget(insn gapstone.Instruction) (AS.VA, error) {
	// have the following possibilities:
	//   - direct jump: jmp 0x1000
	//   - indirect jump: jmp eax
	//   - indirect jump: jmp [0x1000]???

	if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
		return AS.VA(insn.X86.Operands[0].Imm), nil
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_REG {
		// jump eax
		// this is indirect, which is unresolvable.
		// leave analysis to the emulator.
		return AS.VA(0), ErrFailedToResolveJumpTarget
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
		// jump [0x1000]
		// calling this indirect for now, which is unresolvable.
		// we could attempt to manually read out the pointer contents
		//  but that should really be left to the emulator.
		return AS.VA(0), ErrFailedToResolveJumpTarget
	}
	return AS.VA(0), nil
}

// GetJumpTargets gets the possible addresses to which a known jump instruction
//  transfers control.
// For a conditional jump, get both the true and false targets.
// This function uses just the instruction instance, so for an indirect jump, we can't tell much.
func GetJumpTargets(insn gapstone.Instruction) ([]*artifacts.JumpCrossReference, error) {
	ret := make([]*artifacts.JumpCrossReference, 0, 2)

	if DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic == "jmp" {
		// unconditional jump, have the following possibilities:
		//   - direct jump: jmp 0x1000
		//   - indirect jump: jmp eax
		//   - indirect jump: jmp [0x1000]???

		next, e := GetJumpTarget(insn)
		if e != nil {
			// do the best we can
			return ret, nil
		}

		ret = append(
			ret,
			&artifacts.JumpCrossReference{
				CrossReference: artifacts.CrossReference{
					From: AS.VA(insn.Address),
					To:   next,
				},
				Type: artifacts.JumpTypeUncond,
			})
	} else {
		// assume a two case situation:
		//   here:
		//     jnz yes
		//     xor eax, eax
		//     ret
		//   yes:
		//     mov eax, 1
		//     ret
		falsePc := AS.VA(uint64(insn.Address) + uint64(insn.Size))
		ret = append(
			ret,
			&artifacts.JumpCrossReference{
				CrossReference: artifacts.CrossReference{
					From: AS.VA(insn.Address),
					To:   falsePc,
				},
				Type: artifacts.JumpTypeCondFalse,
			})

		truePc, e := GetJumpTarget(insn)
		if e == nil {
			ret = append(
				ret,
				&artifacts.JumpCrossReference{
					CrossReference: artifacts.CrossReference{
						From: AS.VA(insn.Address),
						To:   truePc,
					},
					Type: artifacts.JumpTypeCondTrue,
				})
		}
	}
	return ret, nil
}

func GetInstructionLength(dis *gapstone.Engine, as AS.AddressSpace, va AS.VA) (uint, error) {
	insn, e := ReadInstruction(dis, as, va)
	if e != nil {
		return 0, e

	}
	check(e)

	return insn.Size, nil
}

func IsConditionalJump(insn gapstone.Instruction) bool {
	if DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic != "jmp" {
		return true
	}
	if DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic == "jmp" {
		if insn.Mnemonic == "jmp" && insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
			// jmp 0x1000
			return false
		} else {
			// jmp eax
			return true
		}
	}
	return false
}
