package artifacts

import (
	P "github.com/williballenthin/Lancelot/persistence"
)

const (
	LocationFunction LocationType = iota
	LocationBasicBlock
	LocationString
	LocationUnknown
)

// AddressDataType
const (
	LocationData P.AddressDataType = iota
	FunctionData
	BasicBlockData
)

// AddressDataKeyString
const (
	FunctionName P.AddressDataKeyS = iota
)

// AddressDataKeyNumber
const (
	FunctionStackDelta P.AddressDataKeyI = iota
	TypeOfLocation
)

// EdgeDataType
const (
	// from basic block to basic block
	FlowXrefData P.EdgeDataType = iota
	// from instruction to VA (mem read/write),
	// or VA to VA (pointer
	DataXrefData
	// from function to function
	CallGraphData
)

// EdgeDataKeyString
const (
	XrefName P.EdgeDataKeyS = iota
)

// EdgeDataKeyNumber
const (
	XrefBranchType P.EdgeDataKeyI = iota // this some fake value so we can test
)
