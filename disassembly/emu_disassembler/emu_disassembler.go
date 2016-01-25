package emu_disassembler

import (
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/analysis/function"
	"github.com/williballenthin/Lancelot/disassembly"
	"github.com/williballenthin/Lancelot/emulator"
	P "github.com/williballenthin/Lancelot/persistence"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type todoPath struct {
	state emulator.SnapshotManagerCookie
	va    AS.VA
}

// EmulatingDisassembler is the object that holds the state of a emulating disassembler.
type EmulatingDisassembler struct {
	function_analysis.FunctionEventDispatcher

	// reference:
	ws             *W.Workspace
	symbolResolver W.SymbolResolver

	// own:
	disassembler *gapstone.Engine
	emulator     *emulator.Emulator
	sman         *emulator.SnapshotManager
	codeHook     emulator.CloseableHook
	unmappedHook emulator.CloseableHook
	todo         []todoPath
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

	sman, e := emulator.NewSnapshotManager(emu)
	check(e)

	unmappedHook, e := emu.HookMemUnmapped(func(access int, addr AS.VA, size int, value int64) bool {
		logrus.Warnf("Unmapped: %d %s %d %d", access, addr, size, value)
		return true
	})

	ev, e := function_analysis.NewFunctionEventDispatcher()
	if e != nil {
		return nil, e
	}

	ed := &EmulatingDisassembler{
		ws:             ws,
		symbolResolver: ws,
		disassembler:   d,
		emulator:       emu,
		sman:           sman,
		FunctionEventDispatcher: *ev,
		unmappedHook:            unmappedHook,
	}

	ed.codeHook, e = emu.HookCode(func(addr AS.VA, size uint32) {
		insn, e := disassembly.ReadInstruction(ed.disassembler, ws, addr)
		check(e)
		ev.EmitInstruction(insn)
	})
	check(e)

	return ed, nil
}

func (ed *EmulatingDisassembler) Close() error {
	ed.FunctionEventDispatcher.Close()
	ed.disassembler.Close()
	ed.emulator.Close()
	ed.sman.Close()
	ed.codeHook.Close()
	ed.unmappedHook.Close()
	return nil
}

func (ed *EmulatingDisassembler) pushState(here emulator.SnapshotManagerCookie, va AS.VA) error {
	logrus.Debugf("emu disassembler: adding path: va: %s cookie: %s", va, here)
	ed.todo = append(ed.todo, todoPath{state: here, va: va})
	return nil
}

func (ed *EmulatingDisassembler) popState() error {
	if len(ed.todo) == 0 {
		// TODO: handle a real error
		panic("no paths to explore")
	}
	path := ed.todo[len(ed.todo)-1]
	ed.todo = ed.todo[:len(ed.todo)-1]
	logrus.Debugf("emu disassembler: exploring path: va: %s cookie: %s", path.va, path.state)
	check(ed.sman.RevertUntil(path.state))
	ed.emulator.SetInstructionPointer(path.va)
	return nil
}

// emuldateToCallTargetAndBack emulates the current instruction that should be a
//  CALL instruction, fetches PC after the instruction, and resets
//  the PC and SP registers.
func (ed *EmulatingDisassembler) emulateToCallTargetAndBack() (AS.VA, error) {
	// TODO: assume that current insn is a CALL

	pc := ed.emulator.GetInstructionPointer()
	sp := ed.emulator.GetStackPointer()

	defer func() {
		ed.emulator.SetInstructionPointer(pc)
		ed.emulator.SetStackPointer(sp)
	}()

	e := ed.emulator.StepInto()
	if e != nil {
		logrus.Warnf("Failed to resolve call target: %s: %s", pc, e.Error())
		return 0, e
	}

	newPc := ed.emulator.GetInstructionPointer()
	return newPc, nil
}

// ErrFailedToResolveTarget is an error to be used when an
//  analysis routine is unable to determine the target of a
//  control flow instruction.
var ErrFailedToResolveTarget = errors.New("Failed to resolve control flow target")

// discoverCallTarget finds the target of the current instruction that
//  should be a CALL instruction.
// returns ErrFailedToResolveTarget if the target is not resolvable.
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

	insn, e := disassembly.ReadInstruction(ed.disassembler, ed.ws, callVA)
	if e != nil {
		return 0, e
	}

	if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
		// assume we have: call [0x4010000]  ; IAT
		iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
		if e == nil {
			// we successfully resolved an imported function.
			// TODO: how are we marking xrefs to imports? i guess with xrefs to the IAT
			callTarget = iva
		} else {
			// this is not an imported function, so we'll just have to try and see.
			// either there's a valid function pointer at the address, or we'll get an invalid fetch.
			callTarget, e = ed.emulateToCallTargetAndBack()
			if e != nil {
				logrus.Debugf("EmulateBB: emulating: failed to resolve call: %s", callVA)
				return 0, ErrFailedToResolveTarget
			}
		}
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
		// assume we have: call 0x401000
		callTarget = AS.VA(insn.X86.Operands[0].Imm)
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_REG {
		// assume we have: call eax
		callTarget, e = ed.emulateToCallTargetAndBack()
		if e != nil {
			logrus.Debugf("EmulateBB: emulating: failed to resolve call: %s", callVA)
			return 0, ErrFailedToResolveTarget
		}
	}
	return callTarget, nil
}

func (ed *EmulatingDisassembler) emulateToJumpTargetsAndBack() ([]AS.VA, error) {
	// TODO: assume that current insn is a branch of some sort

	set := make(map[AS.VA]bool)

	// rather than do too much inspection (which sounds tedious to program right now),
	//  lets just brute force all possibilities.
	// these are the cases, via http://unixwiz.net/techtips/x86-jumps.html
	//  - EFLAGS all set (OF, SF, ZF, CF, PF)
	//  - EFLAGS none set (OF, SF, ZF, CF, PF)
	//  - CF != OF
	//  - RCX/ECX/CX == 0
	//  - RCX/ECX/CX == 1

	// case one:
	//  - EFLAGS all set (OF, SF, ZF, CF, PF)
	ed.emulator.RegSetEflag(emulator.EFLAG_OF)
	ed.emulator.RegSetEflag(emulator.EFLAG_SF)
	ed.emulator.RegSetEflag(emulator.EFLAG_ZF)
	ed.emulator.RegSetEflag(emulator.EFLAG_CF)
	ed.emulator.RegSetEflag(emulator.EFLAG_PF)
	va, e := ed.emulateToCallTargetAndBack()
	if e != nil {
		logrus.Warn("Failed to resolve branch target: %s", e.Error())
	} else {
		set[va] = true
	}

	// case two:
	//  - EFLAGS none set (OF, SF, ZF, CF, PF)
	ed.emulator.RegUnsetEflag(emulator.EFLAG_OF)
	ed.emulator.RegUnsetEflag(emulator.EFLAG_SF)
	ed.emulator.RegUnsetEflag(emulator.EFLAG_ZF)
	ed.emulator.RegUnsetEflag(emulator.EFLAG_CF)
	ed.emulator.RegUnsetEflag(emulator.EFLAG_PF)
	va, e = ed.emulateToCallTargetAndBack()
	if e != nil {
		logrus.Warn("Failed to resolve branch target: %s", e.Error())
	} else {
		set[va] = true
	}

	// case three:
	//  - CF != OF
	// CF is 0, so set OF to 1
	ed.emulator.RegSetEflag(emulator.EFLAG_OF)
	va, e = ed.emulateToCallTargetAndBack()
	if e != nil {
		logrus.Warn("Failed to resolve branch target: %s", e.Error())
	} else {
		set[va] = true
	}

	// case four:
	//  - RCX/ECX/CX == 0
	ed.emulator.RegWrite(uc.X86_REG_RCX, 0)
	ed.emulator.RegWrite(uc.X86_REG_ECX, 0)
	ed.emulator.RegWrite(uc.X86_REG_CX, 0)
	va, e = ed.emulateToCallTargetAndBack()
	if e != nil {
		logrus.Warn("Failed to resolve branch target: %s", e.Error())
	} else {
		if va != 0 {
			// ignore if we had: jmp ecx
			set[va] = true
		}
	}

	// case five:
	//  - RCX/ECX/CX == 1
	ed.emulator.RegWrite(uc.X86_REG_RCX, 1)
	ed.emulator.RegWrite(uc.X86_REG_ECX, 1)
	ed.emulator.RegWrite(uc.X86_REG_CX, 1)
	va, e = ed.emulateToCallTargetAndBack()
	if e != nil {
		logrus.Warn("Failed to resolve branch target: %s", e.Error())
	} else {
		if va != 1 {
			// ignore if we had: jmp ecx
			set[va] = true
		}
	}

	ret := make([]AS.VA, 0, len(set))
	for va := range set {
		ret = append(ret, va)
	}

	return ret, nil
}

func ProbeMemory(as AS.AddressSpace, va AS.VA, size uint64) bool {
	_, e := as.MemRead(va, size)
	return e == nil
}

func (ed *EmulatingDisassembler) findJumpTableTargets(disp AS.VA, scale int) ([]AS.VA, error) {
	var targets []AS.VA
	va := disp
	for {
		logrus.Debugf("pointer read: %s", va)
		target, e := W.MemReadPointer(ed.emulator, va, ed.emulator.GetMode())
		check(e)

		if ProbeMemory(ed.emulator, target, uint64(scale)) {
			targets = append(targets, target)
			// not sure this conversion from negative number to uint64 is correct
			va = AS.VA(uint64(va) + uint64(scale))
		} else {
			break
		}
	}
	return targets, nil
}

// discoverJumpTargets finds the targets of the current instruction that
//  should be a jump/branch instruction.
// returns ErrFailedToResolveTarget if the target is not resolvable.
// this should be expected in some cases, like jumping into uninitialized memory.
func (ed *EmulatingDisassembler) discoverJumpTargets() ([]AS.VA, error) {
	jumpVA := ed.emulator.GetInstructionPointer()

	insn, e := disassembly.ReadInstruction(ed.disassembler, ed.ws, jumpVA)
	if e != nil {
		return nil, e
	}

	var jumpTargets []AS.VA
	if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
		// simple case:
		// this looks like: jnz 0x401000
		jumpTargets = []AS.VA{AS.VA(insn.X86.Operands[0].Imm)}
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
		// complex cases:
		op := insn.X86.Operands[0]
		if op.Mem.Base == 0 {
			// this can look like: jmp dword ptr [edx*4 + 0x401000]
			// segment: 0
			// base: 0
			// index: 0x18 (X86_REG_EDX)
			// scale: 4
			// disp: 0x401000
			jumpTargets, e = ed.findJumpTableTargets(AS.VA(op.Mem.Disp), op.Mem.Scale)
			check(e)
		} else {
			// or this can look like: jmp dword ptr [0x401000]
			//
			// or this:  jmp dword ptr [ebx + 0x18]"
			// segment: 0
			// base: 0x15 (X86_REG_EBX)
			// index: 0
			// scale: 1
			// disp: 0x18
			jumpTargets, e = ed.emulateToJumpTargetsAndBack()
			check(e)
		}
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_REG {
		// complex case:
		// this can look like: jmp [edx]
		jumpTargets, e = ed.emulateToJumpTargetsAndBack()
		check(e)
	} else {
		// this shouldnt really happen. the remaining types are: INVALID, and FP
		logrus.Debugf("jump target type: %x", insn.X86.Operands[0].Type)
		jumpTargets, e = ed.emulateToJumpTargetsAndBack()
		check(e)
	}

	if disassembly.IsConditionalJump(insn) {
		logrus.Debugf("conditional jump")
		jumpTargets = append(jumpTargets, AS.VA(insn.Address+insn.Size))
	}
	return jumpTargets, nil
}

func SkipInstruction(emu *emulator.Emulator, dis *gapstone.Engine) error {

	pc := emu.GetInstructionPointer()
	insn, e := disassembly.ReadInstruction(dis, emu, pc)
	check(e)

	nextPc := AS.VA(insn.Address + insn.Size)
	logrus.Debugf("Skipping from %s to %s", pc, nextPc)
	emu.SetInstructionPointer(nextPc)
	return nil
}

func (ed *EmulatingDisassembler) bulletproofRun(dest AS.VA) error {
	for ed.emulator.GetInstructionPointer() != dest {
		e := ed.emulator.RunTo(dest)
		if e == AS.ErrUnmappedMemory {
			pc := ed.emulator.GetInstructionPointer()
			// TODO: mark these instruction in the workspace
			logrus.Warnf("EmulateBB: invalid fetch during emulation, but carrying on: %s: %s", pc, e.Error())
			check(SkipInstruction(ed.emulator, ed.disassembler))
		} else if e != nil {
			logrus.Warnf("EmulateBB: emulation failed: %s", e.Error())
			return e
		}
	}
	return nil
}

// when/where can this function be safely called?
func (ed *EmulatingDisassembler) ExploreBB(as AS.AddressSpace, va AS.VA) ([]AS.VA, error) {
	logrus.Debugf("emu disassembler: explore bb: %s", va)

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
	var nextBBs []AS.VA
	bbStart := va
	var callVAs []AS.VA

	// recon
	endVA := va
	e := disassembly.IterateInstructions(ed.disassembler, as, va, func(insn gapstone.Instruction) (bool, error) {
		logrus.Debugf("recon: insn: %s", AS.VA(insn.Address))
		endVA = AS.VA(insn.Address) // update last reached VA, to compute end of BB
		if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			return true, nil
		}

		logrus.Debugf("EmulateBB: planning: found call: va: 0x%x", insn.Address)
		callVAs = append(callVAs, AS.VA(insn.Address))
		return true, nil // continue processing instructions
	})
	check(e)

	// prepare emulator
	ed.emulator.SetInstructionPointer(va)

	// emulate!
	for len(callVAs) > 0 {
		callVA := callVAs[0]
		callVAs = callVAs[1:]

		logrus.Debugf("EmulateBB: emulating: from: %s to: %s", ed.emulator.GetInstructionPointer(), callVA)

		e := ed.bulletproofRun(callVA)
		check(e)

		pc := ed.emulator.GetInstructionPointer()

		insn, e := disassembly.ReadInstruction(ed.disassembler, ed.ws, pc)
		check(e)
		if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			panic(fmt.Sprintf("expected to be at a call, but we're not: %s", pc))
		}
		logrus.Debugf("EmulateBB: paused at call: %s", pc)
		// this instruction may be emitted twice, since we potentially
		//  use emulation to resolve the call target
		check(ed.EmitInstruction(insn))

		var stackDelta int64
		callTarget, e := ed.discoverCallTarget()
		if e == ErrFailedToResolveTarget {
			// will just have to make a guess as to how to clean up the stack
			// for right now, assume its 0
			// TODO: if its an import, assume STDCALL
			//  and use MSDN documentation to extract number of parameters
		} else if e != nil {
			e := ed.ws.MakeFunction(callTarget)
			check(e)

			f, e := ed.ws.Artifacts.GetFunction(callTarget)
			check(e)

			stackDelta, e = f.GetStackDelta()
			check(e)
		}
		check(ed.EmitCall(pc, callTarget))

		logrus.Debugf("EmulateBB: skipping call: %s", pc)
		check(SkipInstruction(ed.emulator, ed.disassembler))

		// cleanup stack
		ed.emulator.SetStackPointer(AS.VA(int64(ed.emulator.GetStackPointer()) + stackDelta))
	}

	// emulate to end of current basic block
	logrus.Debugf("EmulateBB: emulating to end: from: %s to: %s", ed.emulator.GetInstructionPointer(), endVA)
	e = ed.bulletproofRun(endVA)
	check(e)

	pc := ed.emulator.GetInstructionPointer()
	check(ed.EmitBB(bbStart, pc))

	insn, e := disassembly.ReadInstruction(ed.disassembler, ed.ws, pc)
	check(e)

	logrus.Debugf("EmulateBB: final instruction: %s", pc)
	check(ed.EmitInstruction(insn))

	if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
		logrus.Debugf("EmulateBB: ends with a ret")
	} else {
		// must be a jump
		nextBBs, e = ed.discoverJumpTargets()
		check(e)

		logrus.Debugf("EmulateBB: next BBs: %v", nextBBs)

		for _, target := range nextBBs {
			// TODO: use real jump types
			check(ed.EmitJump(insn, bbStart, target, P.JumpTypeUncond))
		}
	}
	return nextBBs, nil
}

// ExploreFunction uses an emulator to disassemble instructions and explore basic
//  blocks starting at a given address in a given address space, invoking
//  appropriate callbacks.
// It terminates once it has explored all the basic blocks it discovers.
// TODO: what is `as` for?
func (ed *EmulatingDisassembler) ExploreFunction(as AS.AddressSpace, va AS.VA) error {
	logrus.Debugf("emu disassembler: explore function: %s", va)

	ed.emulator.SetInstructionPointer(va)
	here, e := ed.sman.Push()
	check(e)
	ed.pushState(here, va)

	// the set of explored BBs, by BB start address
	doneBBs := map[AS.VA]bool{}

	for len(ed.todo) > 0 {
		ed.popState()
		pc := ed.emulator.GetInstructionPointer()

		_, done := doneBBs[pc]
		if done {
			continue
		}

		doneBBs[pc] = true
		next, e := ed.ExploreBB(as, pc)
		if e != nil {
			return e
		}

		here, e := ed.sman.Push()
		check(e)
		for _, n := range next {
			ed.pushState(here, n)
		}
	}

	return nil
}
