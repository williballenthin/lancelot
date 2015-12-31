package dora

import (
	"github.com/bnagy/gapstone"
	w "github.com/williballenthin/Lancelot/workspace"
	"log"
)

type BasicBlock struct {
	// Start is the first address in the basic block.
	Start w.VA
	// End is the last address in the basic block.
	End w.VA
}

type CrossReference struct {
	// From is the address from which the xref references.
	From w.VA
	// To is the address to which the xref references.
	To w.VA
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

// InstructionTraceHandler is a function that can process instructions
//  parsed by this package.
// Use insn.Address for the current address.
type InstructionTraceHandler func(insn gapstone.Instruction) error

// JumpTraceHandler is a function that can process control flow edges
//  parsed by this package.
// Use insn.Address for the source address.
// Use bb for the address of the source basic block.
type JumpTraceHandler func(insn gapstone.Instruction, xref *JumpCrossReference) error

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
