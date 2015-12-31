package dora

import (
	"github.com/bnagy/gapstone"
	w "github.com/williballenthin/Lancelot/workspace"
	"log"
)

type BasicBlock struct {
	Start w.VA
	End   w.VA
}

type CrossReference struct {
	From w.VA
	To   w.VA
}

type MemoryWriteCrossReference CrossReference
type MemoryReadCrossReference CrossReference
type CallCrossReference CrossReference

// JumpType defines the possible types of intra-function edges.
type JumpType string

// JumpTypeCondTrue is the JumpType that represents the True
//  edge of a conditional branch.
var JumpTypeCondTrue JumpType = "jtrue"

// JumpTypeCondFalse is the JumpType that represents the False
//  edge of a conditional branch.
var JumpTypeCondFalse JumpType = "jfalse"

// JumpTypeUncond is the JumpType that represents the edge of
//  an unconditional branch.
var JumpTypeUncond JumpType = "juncond"

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
