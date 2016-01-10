package emu_disassembler

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/analysis/function"
	"github.com/williballenthin/Lancelot/disassembly"
	"github.com/williballenthin/Lancelot/emulator"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// EmulatingDisassembler is the object that holds the state of a emulating disassembler.
type EmulatingDisassembler struct {
	function_analysis.FunctionEventDispatcher

	ws             *W.Workspace
	symbolResolver W.SymbolResolver
	disassembler   *gapstone.Engine
	emulator       *emulator.Emulator
	codeHook       emulator.CloseableHook
}

// New creates a new EmulatingDisassembler instance.
func New(ws *W.Workspace) (*EmulatingDisassembler, error) {
	// maybe the disassembler shouldn't come from the workspace directly?
	d, e := disassembly.New(ws)
	if e != nil {
		return nil, e
	}

	// note: we could easily emulate over a memory/debugger/emulator state
	// by using a different address space here.
	emu, e := emulator.New(ws)
	if e != nil {
		return nil, e
	}
	ev, e := function_analysis.NewFunctionEventDispatcher()
	if e != nil {
		return nil, e
	}

	ed := &EmulatingDisassembler{
		ws:                      ws,
		symbolResolver:          ws,
		disassembler:            d,
		emulator:                emu,
		FunctionEventDispatcher: *ev,
	}

	ed.codeHook, e = emu.HookCode(func(addr AS.VA, size uint32) {
		check(e)
		insn, e := disassembly.ReadInstruction(ed.disassembler, ws, addr)
		ev.EmitInstruction(insn)
	})
	check(e)

	return ed, nil
}

func (ed *EmulatingDisassembler) Close() error {
	ed.codeHook.Close()
	ed.emulator.Close()
}

// emuldateToCallTargetAndBack emulates the current instruction that should be a
//  CALL instruction, fetches PC after the instruction, and resets
//  the PC and SP registers.
func (ed *EmulatingDisassembler) emulateToCallTargetAndBack() (AS.VA, error) {
	// TODO: assume that current insn is a CALL

	pc := ed.emulator.GetInstructionPointer()
	sp := ed.emulator.GetStackPointer()

	e := ed.emulator.StepInto()
	check(e)
	if e != nil {
		return 0, e
	}

	newPc := ed.emulator.GetInstructionPointer()
	ed.emulator.SetInstructionPointer(pc)
	ed.emulator.SetStackPointer(sp)

	return newPc, nil
}

// ErrFailedToResolveCallTarget is an error to be used when an
//  analysis routine is unable to determine the target of a CALL
//  instruction.
var ErrFailedToResolveCallTarget = errors.New("Failed to resolve call target")

// discoverCallTarget finds the target of the current instruction that
//  should be a CALL instruction.
// returns ErrFailedToResolveCallTarget if the target is not resolvable.
// this should be expected in some cases, like calling into uninitialized memory.
//
// find call target
//   - is direct call, like: call 0x401000
//     -> directly read target
//   - is direct call, like: call [0x401000] ; via IAT
//     -> read IAT, use MSDN doc to determine number of args?
//   - is indirect call, like: call EAX
//     -> just save PC, step into, read PC, restore PC, pop SP
//     but be sure to handle invalid fetch errors
func (ed *EmulatingDisassembler) discoverCallTarget() (AS.VA, error) {
	var callTarget AS.VA
	callVA := ed.emulator.GetInstructionPointer()

	insn, e := disassembly.ReadInstruction(ed.disassembler, ed.as, callVA)
	if e != nil {
		return 0, e
	}

	if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
		// assume we have: call [0x4010000]  ; IAT
		iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
		sym, e := ed.symbolResolver.ResolveAddressToSymbol(iva)
		if e == nil {
			// we successfully resolved an imported function.
			// TODO: how are we marking xrefs to imports? i guess with xrefs to the IAT
			callTarget = iva
		} else {
			// this is not an imported function, so we'll just have to try and see.
			// either there's a valid function pointer at the address, or we'll get an invalid fetch.
			callTarget, e = ed.discoverCallTarget()
			if e != nil {
				logrus.Debug("EmulateBB: emulating: failed to resolve call: 0x%x", callVA)
				return 0, ErrFailedToResolveCallTarget
			}
		}
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
		// assume we have: call 0x401000
		callTarget := AS.VA(insn.X86.Operands[0].Imm)
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_REG {
		// assume we have: call eax
		callTarget, e = ed.discoverCallTarget()
		if e != nil {
			logrus.Debug("EmulateBB: emulating: failed to resolve call: 0x%x", callVA)
			return 0, ErrFailedToResolveCallTarget
		}
	}
	return callTarget, nil
}

// when/where can this function be safely called?
func (ed *EmulatingDisassembler) EmulateBB(as AS.AddressSpace, va AS.VA) ([]AS.VA, error) {
	// things done here:
	//  - find CALL instructions
	//  - emulate to CALL instructions
	//     - using emulation, figure out what the target of the call is
	//     - using linear disassembly, find target calling convention
	//     - decide how much stack to clean up
	//  - manually move PC to instruction after the CALL
	//  - clean up stack
	//  - continue emulating
	//  - resolve jump targets at end of BB using emulation
	logrus.Debug("EmulateBB: va: 0x%x", va)

	nextBBs := make([]AS.VA, 0, 2)
	var callVAs []AS.VA

	// recon
	endVA := va
	e := disassembly.IterateInstructions(ed.disassembler, as, va, func(insn gapstone.Instruction) (bool, error) {
		if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			return true, nil
		}

		logrus.Debug("EmulateBB: planning: found call: va: 0x%x", insn.Address)
		callVAs = append(callVAs, AS.VA(insn.Address))
		endVA = AS.VA(insn.Address) // update last reached VA, to compute end of BB
		return true, nil            // continue processing instructions
	})
	check(e)

	// prepare emulator
	ed.emulator.SetInstructionPointer(va)

	// emulate!
	for len(callVAs) > 0 {
		callVA := callVAs[0]
		callVAs = callVAs[1:]

		logrus.Debug("EmulateBB: emulating: from: 0x%x to: 0x%x", ed.emulator.GetInstructionPointer(), callVA)
		e := ed.emulator.RunTo(callVA)
		check(e)

		// call insn
		insn, e := disassembly.ReadInstruction(ed.disassembler, ed.as, callVA)
		check(e)

		var stackDelta int64
		callTarget, e := ed.discoverCallTarget()
		if e == ErrFailedToResolveCallTarget {
			// will just have to make a guess as to how to clean up the stack
		} else if e != nil {
			e := ed.ws.MakeFunction(callTarget)
			check(e)

			f, e := ed.ws.Artifacts.GetFunction(callTarget)
			check(e)

			stackDelta, e = f.GetStackDelta()
			check(e)
		}

		check(ed.EmitCall(callVA, callTarget))

		// skip call instruction
		ed.emulator.SetInstructionPointer(AS.VA(insn.Address + insn.Size))

		// cleanup stack
		ed.emulator.SetStackPointer(AS.VA(int64(ed.emulator.GetStackPointer()) + stackDelta))
	}

	// emulate to end of current basic block
	logrus.Debug("EmulateBB: emulating to end: from: 0x%x to: 0x%x", ed.emulator.GetInstructionPointer(), endVA)
	e = ed.emulator.RunTo(endVA)
	check(e)

	// find jump targets
	//  - is direct jump, like: jmp 0x401000
	//     -> read target
	//  - is indirect jump, like: jmp EAX
	//     -> just save PC, step into, read PC, restore PC
	//     but be sure to handle invalid fetch errors
	return nextBBs, nil
}
