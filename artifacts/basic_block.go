package artifacts

import (
	AS "github.com/williballenthin/Lancelot/address_space"
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

func (f *BasicBlock) SetName(name string) error {
	return f.artifacts.persistence.SetAddressValueString(P.BasicBlockData, f.Start, P.BasicBlockName, name)
}

func (f *BasicBlock) GetName() (string, error) {
	return f.artifacts.persistence.GetAddressValueString(P.BasicBlockData, f.Start, P.BasicBlockName)
}
