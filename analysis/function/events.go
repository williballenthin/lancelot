package function_analysis

import (
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
)

// InstructionTraceHandler is a function that can process instructions
//  parsed by this package.
// Use insn.Address for the current address.
type InstructionTraceHandler func(insn gapstone.Instruction) error

// JumpTraceHandler is a function that can process control flow edges
//  parsed by this package.
// Use insn.Address for the source address.
// Use bb for the address of the source basic block.
type JumpTraceHandler func(insn gapstone.Instruction, from_bb AS.VA, target AS.VA, jtype P.JumpType) error

type BBTraceHandler func(start AS.VA, end AS.VA) error

type CallTraceHandler func(callSite AS.VA, callTarget AS.VA) error

type Cookie uint64

type FunctionEventDispatcher struct {
	counter      Cookie
	insnHandlers map[Cookie]InstructionTraceHandler
	jumpHandlers map[Cookie]JumpTraceHandler
	bbHandlers   map[Cookie]BBTraceHandler
	callHandlers map[Cookie]CallTraceHandler
}

func NewFunctionEventDispatcher() (*FunctionEventDispatcher, error) {
	return &FunctionEventDispatcher{
		counter:      Cookie(0),
		insnHandlers: make(map[Cookie]InstructionTraceHandler),
		jumpHandlers: make(map[Cookie]JumpTraceHandler),
		bbHandlers:   make(map[Cookie]BBTraceHandler),
		callHandlers: make(map[Cookie]CallTraceHandler),
	}, nil
}

// RegisterInstructionTraceHandler adds a callback function to receive the
//   disassembled instructions.
func (ev *FunctionEventDispatcher) RegisterInstructionTraceHandler(fn InstructionTraceHandler) (Cookie, error) {
	ev.counter++
	c := ev.counter
	ev.insnHandlers[c] = fn
	return c, nil
}

// UnregisterInstructionTraceHandler removes a previously-added callback
//   function to receive the disassembled instructions.
func (ev *FunctionEventDispatcher) UnregisterInstructionTraceHandler(c Cookie) error {
	delete(ev.insnHandlers, c)
	return nil
}

func (ev *FunctionEventDispatcher) EmitInstruction(insn gapstone.Instruction) error {
	for _, f := range ev.insnHandlers {
		e := f(insn)
		if e != nil {
			logrus.Warnf("Instruction handler failed: %s", e.Error())
		}
	}
	return nil
}

func (ev *FunctionEventDispatcher) RegisterBBTraceHandler(fn BBTraceHandler) (Cookie, error) {
	ev.counter++
	c := ev.counter
	ev.bbHandlers[c] = fn
	return c, nil
}

func (ev *FunctionEventDispatcher) UnregisterBBTraceHandler(c Cookie) error {
	delete(ev.bbHandlers, c)
	return nil
}
func (ev *FunctionEventDispatcher) EmitBB(start AS.VA, end AS.VA) error {
	for _, f := range ev.bbHandlers {
		e := f(start, end)
		if e != nil {
			logrus.Warnf("Basic block handler failed: %s", e.Error())
		}
	}
	return nil
}

// RegisterJumpTraceHandler adds a callback function to receive control flow
//  edges identified among basic blocks.
func (ev *FunctionEventDispatcher) RegisterJumpTraceHandler(fn JumpTraceHandler) (Cookie, error) {
	ev.counter++
	c := ev.counter
	ev.jumpHandlers[c] = fn
	return c, nil
}

// UnregisterJumpTraceHandler removes a previously-added callback
//   function to receive control flow edges identified among basic blocks.
func (ev *FunctionEventDispatcher) UnregisterJumpTraceHandler(c Cookie) error {
	delete(ev.jumpHandlers, c)
	return nil
}

func (ev *FunctionEventDispatcher) EmitJump(insn gapstone.Instruction, from_bb AS.VA, target AS.VA, jtype P.JumpType) error {
	for _, f := range ev.jumpHandlers {
		e := f(insn, from_bb, target, jtype)
		if e != nil {
			logrus.Warnf("Jump handler failed: %s", e.Error())
		}
	}
	return nil
}

func (ev *FunctionEventDispatcher) RegisterCallTraceHandler(fn CallTraceHandler) (Cookie, error) {
	ev.counter++
	c := ev.counter
	ev.callHandlers[c] = fn
	return c, nil
}

func (ev *FunctionEventDispatcher) UnregisterCallTraceHandler(c Cookie) error {
	delete(ev.callHandlers, c)
	return nil
}

func (ev *FunctionEventDispatcher) EmitCall(callSite AS.VA, callTarget AS.VA) error {
	for _, f := range ev.callHandlers {
		e := f(callSite, callTarget)
		if e != nil {
			logrus.Warnf("Call handler failed: %s", e.Error())
		}
	}
	return nil
}
