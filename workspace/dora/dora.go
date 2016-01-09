package dora

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	dis "github.com/williballenthin/Lancelot/disassembly"
	E "github.com/williballenthin/Lancelot/emulator"
	P "github.com/williballenthin/Lancelot/persistence"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// InstructionTraceHandler is a function that can process instructions
//  parsed by this package.
// Use insn.Address for the current address.
type InstructionTraceHandler func(insn gapstone.Instruction) error

// JumpTraceHandler is a function that can process control flow edges
//  parsed by this package.
// Use insn.Address for the source address.
// Use bb for the address of the source basic block.
type JumpTraceHandler func(insn gapstone.Instruction, from_bb AS.VA, target AS.VA, jtype P.JumpType) error

func isBBEnd(insn gapstone.Instruction) bool {
	return dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET)
}

func GetNextInstructionPointer(emu *E.Emulator, sman *E.SnapshotManager) (AS.VA, error) {
	var va AS.VA
	e := sman.WithTempExcursion(func() error {
		e := emu.StepInto()
		if e != nil {
			return e
		}
		va = emu.GetInstructionPointer()
		return nil
	})
	return va, e
}
