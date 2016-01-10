// Package linear_disassembler implements a code explorer that uses linear
//  disassembly to recognize instructions, basic blocks, and control
//  flow edges.
package linear_disassembler

import (
	//	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/analysis/function"
	"github.com/williballenthin/Lancelot/disassembly"
	w "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// LinearDisassembler is the object that holds the state of a linear disassembler.
type LinearDisassembler struct {
	function_analysis.FunctionEventDispatcher
	disassembler *gapstone.Engine
}

// New creates a new LinearDisassembler instance.
func New(ws *w.Workspace) (*LinearDisassembler, error) {
	// maybe the disassembler shouldn't come from the workspace directly?
	d, e := disassembly.New(ws)
	if e != nil {
		return nil, e
	}
	ev, e := function_analysis.NewFunctionEventDispatcher()
	if e != nil {
		return nil, e
	}

	return &LinearDisassembler{
		FunctionEventDispatcher: *ev,
		disassembler:            d,
	}, nil
}

// move to utils
func min(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// ExploreBB linearly disassembles instructions starting at a given address
//  in a given address space, invoking the appropriate callbacks, and terminates
//  at the end of the current basic block.
// A basic block is delimited by a ret or jump instruction.
// Returns the addresses to which this basic block may transfer control via jumps.
func (ld *LinearDisassembler) ExploreBB(as AS.AddressSpace, va AS.VA) ([]AS.VA, error) {
	bbStart := va
	// the last VA reached while exploring tihs BB
	// only makes sense to fetch this value after iterating instructions
	lastVa := AS.VA(0)
	nextBBs := make([]AS.VA, 0, 2)

	e := disassembly.IterateInstructions(ld.disassembler, as, va, func(insn gapstone.Instruction) (bool, error) {
		lastVa = AS.VA(insn.Address)
		check(ld.EmitInstruction(insn))

		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) {
			// this return a slice with zero length, but that should be ok
			targets, e := disassembly.GetJumpTargets(insn)
			if e != nil {
				return false, e
			}

			for _, target := range targets {
				check(ld.EmitJump(insn, bbStart, target.To, target.Type))
				nextBBs = append(nextBBs, target.To)
			}

			// though we can assume that IterateInstructions will return after this insn (end of bb),
			//  we'd better not make assumptions. here, we explicityly end processing.
			return false, nil // continue processing instructions
		}

		return true, nil // continue processing instructions
	})
	check(e)

	check(ld.EmitBB(bbStart, lastVa))

	return nextBBs, nil
}

// ExploreFunction linearly disassembles instructions and explores basic
//  blocks starting at a given address in a given address space, invoking
//  appropriate callbacks.
// It terminates once it has explored all the basic blocks it discovers.
func (ld *LinearDisassembler) ExploreFunction(as AS.AddressSpace, va AS.VA) error {
	// lifo is a stack (cause these are easier than queues in Go) of BBs
	//  that need to be explored.
	lifo := make([]AS.VA, 0, 10)
	lifo = append(lifo, va)

	// the set of explored BBs, by BB start address
	doneBBs := map[AS.VA]bool{}

	for len(lifo) > 0 {
		// pop BB address
		bb := lifo[len(lifo)-1]
		lifo = lifo[:len(lifo)-1]

		_, done := doneBBs[bb]
		if done {
			continue
		}

		doneBBs[bb] = true
		next, e := ld.ExploreBB(as, bb)
		if e != nil {
			return e
		}

		// push new BB addresses
		lifo = append(lifo, next...)
	}

	return nil
}
