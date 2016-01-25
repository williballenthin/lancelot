package artifacts

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/disassembly"
	P "github.com/williballenthin/Lancelot/persistence"
)

// unique: (Start)
type BasicBlock struct {
	artifacts *Artifacts
	// Start is the first address in the basic block.
	Start AS.VA
	// End is the last address in the basic block.
	End AS.VA
}

func (bb *BasicBlock) SetName(name string) error {
	return bb.artifacts.persistence.SetAddressValueString(P.BasicBlockData, bb.Start, P.BasicBlockName, name)
}

func (bb *BasicBlock) GetName() (string, error) {
	return bb.artifacts.persistence.GetAddressValueString(P.BasicBlockData, bb.Start, P.BasicBlockName)
}

func (bb *BasicBlock) GetInstructions(dis disassembly.Disassembler, as AS.AddressSpace) ([]gapstone.Instruction, error) {
	var instructions []gapstone.Instruction
	e := dis.IterateInstructions(as, bb.Start, func(insn gapstone.Instruction) (bool, error) {
		instructions = append(instructions, insn)
		return true, nil
	})
	return instructions, e
}
