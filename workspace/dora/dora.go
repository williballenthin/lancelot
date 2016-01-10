package dora

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	dis "github.com/williballenthin/Lancelot/disassembly"
	E "github.com/williballenthin/Lancelot/emulator"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

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
