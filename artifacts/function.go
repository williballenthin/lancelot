package artifacts

import (
	AS "github.com/williballenthin/Lancelot/address_space"
)

// unique: (Start)
type Function struct {
	artifacts *Artifacts

	Start AS.VA // this is implicitly the start of the first BasicBlock
}

func (f *Function) SetName(name string) error {
	return f.artifacts.persistence.SetAddressValueString(FunctionData, f.Start, FunctionName, name)
}

func (f *Function) GetName() (string, error) {
	return f.artifacts.persistence.GetAddressValueString(FunctionData, f.Start, FunctionName)
}

func (f *Function) SetStackDelta(delta int64) error {
	return f.artifacts.persistence.SetAddressValueNumber(FunctionData, f.Start, FunctionStackDelta, delta)
}

func (f *Function) GetStackDelta() (int64, error) {
	return f.artifacts.persistence.GetAddressValueNumber(FunctionData, f.Start, FunctionStackDelta)
}
