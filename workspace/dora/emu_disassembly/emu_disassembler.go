package EmulatingDisassembler

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/disassembly"
	"github.com/williballenthin/Lancelot/emulator"
	W "github.com/williballenthin/Lancelot/workspace"
	"github.com/williballenthin/Lancelot/workspace/dora"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ED is the object that holds the state of a emulating disassembler.
type ED struct {
	as             AS.AddressSpace
	symbolResolver W.SymbolResolver
	disassembler   *gapstone.Engine
	emulator       *emulator.Emulator
	insnHandlers   []dora.InstructionTraceHandler
	jumpHandlers   []dora.JumpTraceHandler

	codeHook emulator.CloseableHook
}

// New creates a new EmulatingDisassembler instance.
func New(ws *W.Workspace, as AS.AddressSpace) (*ED, error) {
	// maybe the disassembler shouldn't come from the workspace directly?
	d, e := disassembly.New(ws)
	if e != nil {
		return nil, e
	}

	// TODO: should we be emulating over the AS instead?
	// then, what is ws used for? -> config, arch, results...
	// so would use look like: ed := New(ws, ws)
	emu, e := emulator.New(ws)
	if e != nil {
		return nil, e
	}

	ed := &ED{
		as:             emu, // note: our AS is the emu, since it may change state.
		symbolResolver: ws,
		disassembler:   d,
		emulator:       emu,
		insnHandlers:   make([]dora.InstructionTraceHandler, 0, 1),
		jumpHandlers:   make([]dora.JumpTraceHandler, 0, 1),
	}

	ed.codeHook, e = emu.HookCode(func(addr AS.VA, size uint32) {
		for _, fn := range ed.insnHandlers {
			insn, e := disassembly.ReadInstruction(ed.disassembler, ed.as, addr)
			check(e)
			e = fn(insn)
			check(e)
		}
	})
	check(e)

	return ed, nil
}

func (ed *ED) Close() error {
	ed.codeHook.Close()
	ed.emulator.Close()
}

// RegisterInstructionTraceHandler adds a callback function to receive the
//   disassembled instructions.
// This may be called for more instructions than are strictly in the targetted function, BB.
// TODO: document this more.
func (ed *ED) RegisterInstructionTraceHandler(fn dora.InstructionTraceHandler) error {
	ed.insnHandlers = append(ed.insnHandlers, fn)
	return nil
}

// RegisterJumpTraceHandler adds a callback function to receive control flow
//  edges identified among basic blocks.
func (ed *ED) RegisterJumpTraceHandler(fn dora.JumpTraceHandler) error {
	ed.jumpHandlers = append(ed.jumpHandlers, fn)
	return nil
}

func (ed *ED) discoverCallTarget() (AS.VA, error) {
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

// when/where can this function be safely called?
func (ed *ED) EmulateBB(as AS.AddressSpace, va AS.VA) ([]AS.VA, error) {
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
		insn, e := disassembly.ReadInstruction(ed.disassembler, ed.as, addr)
		check(e)

		// find call target
		//   - is direct call, like: call 0x401000
		//     -> read target
		//   - is direct call, like: call [0x401000] ; via IAT
		//     -> read IAT, use MSDN doc to determine number of args?
		//   - is indirect call, like: call EAX
		//     -> just save PC, step into, read PC, restore PC, pop SP
		//     but be sure to handle invalid fetch errors
		if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
			// assume we have: call [0x4010000]  ; IAT
			iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
			sym, e := ed.symbolResolver.ResolveSymbol(iva)
			if e == nil {
				// TODO: this is an imported function
			} else {
				// TODO: ???
			}
		} else if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
			// assume we have: call 0x401000
			targetva := AS.VA(insn.X86.Operands[0].Imm)
			s = s + fmt.Sprintf("  ; sub_%x", targetva)
		}

		// get calling convention

		// invoke CallHandlers
		// skip call instruction

		// cleanup stack
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
