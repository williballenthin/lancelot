package dora

import (
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
type JumpCrossReference CrossReference

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
	log.Printf("bb: %v", bb)
	return nil
}

func (l LoggingArtifactCollection) AddMemoryReadXref(xref MemoryReadCrossReference) error {
	log.Printf("r xref: %v", xref)
	return nil
}

func (l LoggingArtifactCollection) AddMemoryWriteXref(xref MemoryWriteCrossReference) error {
	log.Printf("w xref: %v", xref)
	return nil
}

func (l LoggingArtifactCollection) AddCallXref(xref CallCrossReference) error {
	log.Printf("c xref: %v", xref)
	return nil
}

func (l LoggingArtifactCollection) AddJumpXref(xref JumpCrossReference) error {
	log.Printf("j xref: %v", xref)
	return nil
}
