package EmulatingDisassembler

import (
	"fmt"
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
	as           AS.AddressSpace
	disassembler *gapstone.Engine
	emulator     *emulator.Emulator
	insnHandlers []dora.InstructionTraceHandler
	jumpHandlers []dora.JumpTraceHandler
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

	return &ED{
		as:           emu, // note: our AS is the emu, since it may change state.
		disassembler: d,
		emulator:     emu,
		insnHandlers: make([]dora.InstructionTraceHandler, 0, 1),
		jumpHandlers: make([]dora.JumpTraceHandler, 0, 1),
	}, nil
}

// RegisterInstructionTraceHandler adds a callback function to receive the
//   disassembled instructions.
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

// move to utils
func min(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// FormatAddressDisassembly formats the bytes at a given address in a given
//  address space as disassembly.
// It may also include the hexidecimal bytes alongside the mnemonics and
//  operands if numOpcodeBytes is non-zero.
// This function returns the data at va formatted appropriately, the number
//  of bytes for va formatted, and an error instance.
// TODO: move to utils
func FormatAddressDisassembly(dis *gapstone.Engine, as AS.AddressSpace, va AS.VA, numOpcodeBytes uint) (string, uint64, error) {
	insn, e := disassembly.ReadInstruction(dis, as, va)
	check(e)

	numBytes := uint64(numOpcodeBytes)
	d, e := as.MemRead(va, min(uint64(insn.Size), numBytes))
	check(e)

	// format each of those as hex
	var bytesPrefix []string
	for _, b := range d {
		bytesPrefix = append(bytesPrefix, fmt.Sprintf("%02X", b))
	}
	// and fill in padding space
	for i := uint64(len(d)); i < numBytes; i++ {
		bytesPrefix = append(bytesPrefix, "  ")
	}
	prefix := strings.Join(bytesPrefix, " ")

	ret := fmt.Sprintf("0x%x: %s %s\t%s", insn.Address, prefix, insn.Mnemonic, insn.OpStr)
	return ret, uint64(insn.Size), nil
}

// when/where can this function be safely called?
func (ed *ED) EmulateBB(as AS.AddressSpace, va AS.VA) ([]AS.VA, error) {
	// things to do:
	//  - find CALL instructions
	//  - emulate to CALL instructions
	//     - using linear disassembly, find target calling convention
	//     - decide how much stack to clean up
	//  - clean up stack
	//  - continue emulating
	//  - resolve jump targets using emulation

	nextBBs := make([]AS.VA, 0, 2)
	var callVAs []AS.VA

	endVA := va
	e := disassembly.IterateInstructions(ed.disassembler, as, va, func(insn gapstone.Instruction) (bool, error) {
		if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			return true, nil
		}

		callVAs = append(callVAs, AS.VA(insn.Address))
		endVA = AS.VA(insn.Address) // update last reached VA, to compute end of BB
		return true, nil            // continue processing instructions
	})
	check(e)

	// prepare emulator
	// but what is actually done in the setup routine vs here?
	ed.emulator.SetInstructionPointer(va)

	// install handlers
	//   - HOOK_CODE handler fires instruction trace handlers
	// though, this should be done in the setup routine?

	for len(callVAs) > 0 {
		callVA := callVAs[0]
		callVAs = callVAs[1:]

		e := ed.emulator.RunTo(callVA)
		check(e)

		// find call target
		//   - is direct call, like: call 0x401000
		//   - is indirect call, like: call EAX

		// get calling convention

		// invoke CallHandlers
		// skip call instruction

		// cleanup stack
	}

	// emulate to end of current basic block
	e = ed.emulator.RunTo(endVA)
	check(e)

	// find jump targets
	//  - is direct jump, like: jmp 0x401000
	//     -> read target
	//  - is indirect jump, like: jmp EAX
	//     -> just save PC, step into, read PC, restore PC
	return nextBBs, nil
}

// ExploreFunction linearly disassembles instructions and explores basic
//  blocks starting at a given address in a given address space, invoking
//  appropriate callbacks.
// It terminates once it has explored all the basic blocks it discovers.
func (ed *ED) ExploreFunction(as w.AddressSpace, va w.VA) error {
	// lifo is a stack (cause these are easier than queues in Go) of BBs
	//  that need to be explored.
	lifo := make([]w.VA, 0, 10)
	lifo = append(lifo, va)

	// the set of explored BBs, by BB start address
	doneBBs := map[w.VA]bool{}

	for len(lifo) > 0 {
		// pop BB address
		bb := lifo[len(lifo)-1]
		lifo = lifo[:len(lifo)-1]

		_, done := doneBBs[bb]
		if done {
			continue
		}

		doneBBs[bb] = true
		next, e := ed.ExploreBB(as, bb)
		if e != nil {
			return e
		}

		// push new BB addresses
		lifo = append(lifo, next...)
	}

	return nil
}
