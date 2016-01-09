// Package linear_disassembler implements a code explorer that uses linear
//  disassembly to recognize instructions, basic blocks, and control
//  flow edges.
package linear_disassembler

import (
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/disassembly"
	w "github.com/williballenthin/Lancelot/workspace"
	dora "github.com/williballenthin/Lancelot/workspace/dora"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Cookie uint64

// LinearDisassembler is the object that holds the state of a linear disassembler.
type LinearDisassembler struct {
	disassembler *gapstone.Engine
	counter      Cookie
	insnHandlers map[Cookie]dora.InstructionTraceHandler
	jumpHandlers map[Cookie]dora.JumpTraceHandler
	bbHandlers   map[Cookie]dora.BBTraceHandler
}

// New creates a new LinearDisassembler instance.
func New(ws *w.Workspace) (*LinearDisassembler, error) {
	// maybe the disassembler shouldn't come from the workspace directly?
	d, e := disassembly.New(ws)
	if e != nil {
		return nil, e
	}
	return &LinearDisassembler{
		disassembler: d,
		insnHandlers: make(map[Cookie]dora.InstructionTraceHandler),
		jumpHandlers: make(map[Cookie]dora.JumpTraceHandler),
		bbHandlers:   make(map[Cookie]dora.BBTraceHandler),
	}, nil
}

// RegisterInstructionTraceHandler adds a callback function to receive the
//   disassembled instructions.
func (ld *LinearDisassembler) RegisterInstructionTraceHandler(fn dora.InstructionTraceHandler) (Cookie, error) {
	ld.counter++
	c := ld.counter
	ld.insnHandlers[c] = fn
	return c, nil
}

// UnregisterInstructionTraceHandler removes a previously-added callback
//   function to receive the disassembled instructions.
func (ld *LinearDisassembler) UnregisterInstructionTraceHandler(c Cookie) error {
	delete(ld.insnHandlers, c)
	return nil
}

// RegisterJumpTraceHandler adds a callback function to receive control flow
//  edges identified among basic blocks.
func (ld *LinearDisassembler) RegisterJumpTraceHandler(fn dora.JumpTraceHandler) (Cookie, error) {
	ld.counter++
	c := ld.counter
	ld.jumpHandlers[c] = fn
	return c, nil
}

// UnregisterJumpTraceHandler removes a previously-added callback
//   function to receive control flow edges identified among basic blocks.
func (ld *LinearDisassembler) UnregisterJumpTraceHandler(c Cookie) error {
	delete(ld.jumpHandlers, c)
	return nil
}

func (ld *LinearDisassembler) RegisterBBTraceHandler(fn dora.BBTraceHandler) (Cookie, error) {
	ld.counter++
	c := ld.counter
	ld.bbHandlers[c] = fn
	return c, nil
}

func (ld *LinearDisassembler) UnregisterBBTraceHandler(c Cookie) error {
	delete(ld.bbHandlers, c)
	return nil
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
		for _, fn := range ld.insnHandlers {
			e := fn(insn)
			if e != nil {
				return false, e
			}
		}

		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) {
			// this return a slice with zero length, but that should be ok
			targets, e := disassembly.GetJumpTargets(insn)
			if e != nil {
				return false, e
			}

			for _, target := range targets {
				for _, fn := range ld.jumpHandlers {
					e := fn(insn, bbStart, target.To, target.Type)
					if e != nil {
						logrus.Warnf("Jump handler failed: %s", e.Error())
						continue
					}
				}
				nextBBs = append(nextBBs, target.To)
			}

			// though we can assume that IterateInstructions will return after this insn (end of bb),
			//  we'd better not make assumptions. here, we explicityly end processing.
			return false, nil // continue processing instructions
		}

		return true, nil // continue processing instructions
	})
	check(e)

	for _, fn := range ld.bbHandlers {
		e := fn(bbStart, lastVa)
		if e != nil {
			logrus.Warnf("Basic block handler failed: %s", e.Error())
			continue
		}
	}

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
