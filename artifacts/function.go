package artifacts

import (
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
)

// unique: (Start)
type Function struct {
	artifacts *Artifacts

	Start AS.VA // this is implicitly the start of the first BasicBlock
}

func (f *Function) SetName(name string) error {
	return f.artifacts.persistence.SetAddressValueString(P.FunctionData, f.Start, P.FunctionName, name)
}

func (f *Function) GetName() (string, error) {
	return f.artifacts.persistence.GetAddressValueString(P.FunctionData, f.Start, P.FunctionName)
}

func (f *Function) SetStackDelta(delta int64) error {
	return f.artifacts.persistence.SetAddressValueNumber(P.FunctionData, f.Start, P.FunctionStackDelta, delta)
}

func (f *Function) GetStackDelta() (int64, error) {
	return f.artifacts.persistence.GetAddressValueNumber(P.FunctionData, f.Start, P.FunctionStackDelta)
}

func (f *Function) GetFirstBasicBlock() (*BasicBlock, error) {
	return f.artifacts.GetBasicBlock(f.Start)
}
