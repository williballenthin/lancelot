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

func (a *Artifacts) GetCodeCrossReferencesFrom(from AS.VA) ([]*CodeCrossReference, error) {
	var ret []*CodeCrossReference
	tos, e := a.persistence.GetEdgesFrom(P.CodeXrefData, from)
	if e != nil {
		return ret, e
	}

	for _, to := range tos {
		xref, e := a.GetCodeCrossReference(from, to)
		check(e)
		ret = append(ret, xref)
	}
	return ret, nil
}

func (a *Artifacts) GetCodeCrossReferencesTo(to AS.VA) ([]*CodeCrossReference, error) {
	var ret []*CodeCrossReference
	froms, e := a.persistence.GetEdgesFrom(P.CodeXrefData, to)
	if e != nil {
		return ret, e
	}

	for _, from := range froms {
		xref, e := a.GetCodeCrossReference(from, to)
		check(e)
		ret = append(ret, xref)
	}
	return ret, nil
}

func (a *Artifacts) AddCallCrossReference(from AS.VA, to AS.VA) (*CallCrossReference, error) {
	// TODO: don't stomp on existing location?
	e := a.persistence.SetEdgeValueNumber(P.CallXrefData, from, to, P.XrefExists, int64(1))
	check(e)

	return &CallCrossReference{
		artifacts: a,
		From:      from,
		To:        to,
	}, nil
}

func (a *Artifacts) GetCallCrossReference(from AS.VA, to AS.VA) (*CallCrossReference, error) {
	_, e := a.persistence.GetEdgeValueNumber(P.CallXrefData, from, to, P.XrefExists)
	if e != nil {
		return nil, ErrXrefNotFound
	}

	return &CallCrossReference{
		artifacts: a,
		From:      from,
		To:        to,
	}, nil
}

func (a *Artifacts) GetCallCrossReferencesFrom(from AS.VA) ([]*CallCrossReference, error) {
	var ret []*CallCrossReference
	tos, e := a.persistence.GetEdgesFrom(P.CallXrefData, from)
	if e != nil {
		return ret, e
	}

	for _, to := range tos {
		xref, e := a.GetCallCrossReference(from, to)
		check(e)
		ret = append(ret, xref)
	}
	return ret, nil
}

func (a *Artifacts) GetCallCrossReferencesTo(to AS.VA) ([]*CallCrossReference, error) {
	var ret []*CallCrossReference
	froms, e := a.persistence.GetEdgesFrom(P.CallXrefData, to)
	if e != nil {
		return ret, e
	}

	for _, from := range froms {
		xref, e := a.GetCallCrossReference(from, to)
		check(e)
		ret = append(ret, xref)
	}
	return ret, nil
}

func (a *Artifacts) AddBasicBlock(start AS.VA, end AS.VA) (*BasicBlock, error) {
	// if theres a function at an address, then there must also be a basic block.
	// function takes precedence.
	v, e := a.persistence.GetAddressValueNumber(P.LocationData, start, P.TypeOfLocation)
	if e != nil && e != P.ErrKeyDoesNotExist {
		return nil, e
	}

	if e == P.ErrKeyDoesNotExist {
		// nothing yet here, mark it as a basic block
		e := a.persistence.SetAddressValueNumber(
			P.LocationData, start, P.TypeOfLocation, int64(P.LocationBasicBlock))
		check(e)

	} else {
		// there is already some data here.

		// if its a function, it takes precendence.
		// else, we mark the location as a basic block.
		if v != int64(P.LocationFunction) {
			// TODO: don't stomp on existing location?
			e := a.persistence.SetAddressValueNumber(
				P.LocationData, start, P.TypeOfLocation, int64(P.LocationBasicBlock))
			check(e)
		}
	}

	length := end - start
	e = a.persistence.SetAddressValueNumber(P.BasicBlockData, start, P.BasicBlockLength, int64(length))
	check(e)

	return &BasicBlock{
		artifacts: a,
		Start:     start,
		End:       end,
	}, nil
}

var ErrBasicBlockNotFound = errors.New("Basic block not found at specified address")

func (a *Artifacts) GetBasicBlock(va AS.VA) (*BasicBlock, error) {
	v, e := a.persistence.GetAddressValueNumber(P.LocationData, va, P.TypeOfLocation)
	if e != nil {
		return nil, ErrBasicBlockNotFound
	}
	switch v {
	case int64(P.LocationFunction):
		// ok
	case int64(P.LocationBasicBlock):
		// ok
	default:
		return nil, ErrFunctionNotFound
	}

	length, e := a.persistence.GetAddressValueNumber(P.BasicBlockData, va, P.BasicBlockLength)
	if e != nil {
		return nil, ErrBasicBlockNotFound
	}

	return &BasicBlock{
		artifacts: a,
		Start:     va,
		End:       AS.VA(uint64(va) + uint64(length)),
	}, nil
}
