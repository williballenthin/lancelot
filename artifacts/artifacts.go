package artifacts

import (
	as "github.com/williballenthin/Lancelot/address_space"
	"log"
)

type BasicBlock struct {
	// Start is the first address in the basic block.
	Start as.VA
	// End is the last address in the basic block.
	End as.VA
}

type CrossReference struct {
	// From is the address from which the xref references.
	From as.VA
	// To is the address to which the xref references.
	To as.VA
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
