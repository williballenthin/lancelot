package artifacts

import (
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
	"log"
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
	// From is the address from which the xref references.
	From AS.VA
	// To is the address to which the xref references.
	To AS.VA
}

type MemoryWriteCrossReference CrossReference
type MemoryReadCrossReference CrossReference
type CallCrossReference CrossReference

type JumpType uint

// JumpType defines the possible types of intra-function edges.
const (
	// JumpTypeCondTrue is the JumpType that represents the True
	//  edge of a conditional branch.
	JumpTypeCondTrue JumpType = iota
	// JumpTypeCondFalse is the JumpType that represents the False
	//  edge of a conditional branch.
	JumpTypeCondFalse
	// JumpTypeUncond is the JumpType that represents the edge of
	//  an unconditional branch.
	JumpTypeUncond
)

func (t JumpType) String() string {
	switch t {
	case JumpTypeCondTrue:
		return "JumpTypeCondTrue"
	case JumpTypeCondFalse:
		return "JumpTypeCondFalse"
	case JumpTypeUncond:
		return "JumpTypeUncond"
	default:
		panic("unexpected JumpType")
	}
}

type JumpCrossReference struct {
	CrossReference
	Type JumpType
}

type ArtifactCollection interface {
	AddBasicBlock(BasicBlock) error
	AddMemoryReadXref(MemoryReadCrossReference) error
	AddMemoryWriteXref(MemoryWriteCrossReference) error
	AddCallXref(CallCrossReference) error
	AddJumpXref(JumpCrossReference) error
}

type LoggingArtifactCollection struct{}

func NewLoggingArtifactCollection() (ArtifactCollection, error) {
	return &LoggingArtifactCollection{}, nil
}

func (l LoggingArtifactCollection) AddBasicBlock(bb BasicBlock) error {
	log.Printf("bb: 0x%x 0x%x", bb.Start, bb.End)
	return nil
}

func (l LoggingArtifactCollection) AddMemoryReadXref(xref MemoryReadCrossReference) error {
	log.Printf("r xref: 0x%x 0x%x", xref.From, xref.To)
	return nil
}

func (l LoggingArtifactCollection) AddMemoryWriteXref(xref MemoryWriteCrossReference) error {
	log.Printf("w xref: 0x%x 0x%x", xref.From, xref.To)
	return nil
}

func (l LoggingArtifactCollection) AddCallXref(xref CallCrossReference) error {
	log.Printf("c xref: 0x%x 0x%x", xref.From, xref.To)
	return nil
}

func (l LoggingArtifactCollection) AddJumpXref(xref JumpCrossReference) error {
	log.Printf("j xref: 0x%x %s 0x%x", xref.From, xref.Type, xref.To)
	return nil
}

type LocationType uint

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
	XrefData      P.EdgeDataType = iota // from basic block to basic block
	CallGraphData                       // from function to function
)

// EdgeDataKeyString
const (
	XrefName P.EdgeDataKeyS = iota
)

// EdgeDataKeyNumber
const (
	XrefBranchType P.EdgeDataKeyI = iota // this some fake value so we can test
)

type Artifacts struct {
	persistence P.Persistence
}

func New(p P.Persistence) (*Artifacts, error) {
	return &Artifacts{
		persistence: p,
	}, nil
}

func (a *Artifacts) AddFunction(va AS.VA) (*Function, error) {
	// TODO: don't stomp on existing location
	e := a.persistence.SetAddressValueNumber(LocationData, va, TypeOfLocation, int64(LocationFunction))
	check(e)

	return &Function{
		artifacts: a,
		Start:     va,
	}, nil
}
