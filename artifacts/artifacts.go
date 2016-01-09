package artifacts

import (
	"errors"
	//	"github.com/Sirupsen/logrus"
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// unique: (Start)
type BasicBlock struct {
	// Start is the first address in the basic block.
	Start AS.VA
	// End is the last address in the basic block.
	End AS.VA
}

// unique: (From, To)
type CrossReference struct {
	artifacts *Artifacts
	// From is the address from which the xref references.
	From AS.VA
	// To is the address to which the xref references.
	To AS.VA
}

type MemoryWriteCrossReference CrossReference
type MemoryReadCrossReference CrossReference
type CallCrossReference CrossReference

type CodeCrossReference struct {
	CrossReference
	Type P.JumpType
}

type Artifacts struct {
	persistence P.Persistence
}

func New(p P.Persistence) (*Artifacts, error) {
	return &Artifacts{
		persistence: p,
	}, nil
}

func (a *Artifacts) AddFunction(va AS.VA) (*Function, error) {
	// TODO: don't stomp on existing location?
	e := a.persistence.SetAddressValueNumber(P.LocationData, va, P.TypeOfLocation, int64(P.LocationFunction))
	check(e)

	return &Function{
		artifacts: a,
		Start:     va,
	}, nil
}

var ErrFunctionNotFound = errors.New("Function not found at specified address")

func (a *Artifacts) GetFunction(va AS.VA) (*Function, error) {
	v, e := a.persistence.GetAddressValueNumber(P.LocationData, va, P.TypeOfLocation)
	if e != nil {
		return nil, ErrFunctionNotFound
	}

	if v != int64(P.LocationFunction) {
		return nil, ErrFunctionNotFound
	}

	return &Function{
		artifacts: a,
		Start:     va,
	}, nil
}

func (a *Artifacts) AddCodeCrossReference(from AS.VA, to AS.VA, jtype P.JumpType) (*CodeCrossReference, error) {
	// TODO: don't stomp on existing location?
	e := a.persistence.SetEdgeValueNumber(P.CodeXrefData, from, to, P.XrefJumpType, int64(jtype))
	check(e)

	return &CodeCrossReference{
		CrossReference: CrossReference{
			artifacts: a,
			From:      from,
			To:        to,
		},
		Type: jtype,
	}, nil
}

var ErrXrefNotFound = errors.New("Cross reference not found at specified address")

// TODO: this does not support two xrefs with same (from, to) with different types
func (a *Artifacts) GetCodeCrossReference(from AS.VA, to AS.VA) (*CodeCrossReference, error) {
	v, e := a.persistence.GetEdgeValueNumber(P.CodeXrefData, from, to, P.XrefJumpType)
	if e != nil {
		return nil, ErrXrefNotFound
	}

	return &CodeCrossReference{
		CrossReference: CrossReference{
			artifacts: a,
			From:      from,
			To:        to,
		},
		Type: P.JumpType(v),
	}, nil
}
