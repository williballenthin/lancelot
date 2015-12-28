// LinearDisassembly implements a code explorer that uses linear
//  disassembly to recognize instructions, basic blocks, and control
//  flow edges.
package LinearDisassembly

import (
	"fmt"
	"github.com/bnagy/gapstone"
	w "github.com/williballenthin/Lancelot/workspace"
	//	"log"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

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

// JumpTarget describes the destination of an edge.
type JumpTarget struct {
	Va       w.VA
	JumpType JumpType
}

// InstructionTraceHandler is a function that can process instructions
//  parsed by this package.
// Use insn.Address for the current address.
type InstructionTraceHandler func(insn gapstone.Instruction) error

// JumpTraceHandler is a function that can process control flow edges
//  parsed by this package.
// Use insn.Address for the source address.
// Use bb for the address of the source basic block.
type JumpTraceHandler func(insn gapstone.Instruction, bb w.VA, jump JumpTarget) error

// LD is the object that holds the state of a linear disassembler.
type LD struct {
	disassembler gapstone.Engine
	insnHandlers []InstructionTraceHandler
	jumpHandlers []JumpTraceHandler
}

// New creates a new LinearDisassembler instance.
func New(ws *w.Workspace) (*LD, error) {
	// maybe the disassembler shouldn't come from the workspace directly?
	d, e := ws.GetDisassembler()
	if e != nil {
		return nil, e
	}
	return &LD{
		disassembler: d,
		insnHandlers: make([]InstructionTraceHandler, 0, 1),
		jumpHandlers: make([]JumpTraceHandler, 0, 1),
	}, nil
}

// RegisterInstructionTraceHandler adds a callback function to receive the
//   disassembled instructions.
func (ld *LD) RegisterInstructionTraceHandler(fn InstructionTraceHandler) error {
	ld.insnHandlers = append(ld.insnHandlers, fn)
	return nil
}

// RegisterJumpTraceHandler adds a callback function to receive control flow
//  edges identified among basic blocks.
func (ld *LD) RegisterJumpTraceHandler(fn JumpTraceHandler) error {
	ld.jumpHandlers = append(ld.jumpHandlers, fn)
	return nil
}

// ReadInstruction fetches bytes from the provided address space at the given
//  address and parses them into a single instruction instance.
// TODO: move to utils
func ReadInstruction(dis gapstone.Engine, as w.AddressSpace, va w.VA) (gapstone.Instruction, error) {
	d, e := as.MemRead(va, uint64(w.MAX_INSN_SIZE))
	check(e)
	if e != nil {
		return gapstone.Instruction{}, w.ErrInvalidMemoryRead
	}

	insns, e := dis.Disasm(d, uint64(va), 1)
	check(e)
	if e != nil {
		return gapstone.Instruction{}, w.FailedToDisassembleInstruction
	}

	if len(insns) == 0 {
		return gapstone.Instruction{}, w.FailedToDisassembleInstruction
	}

	insn := insns[0]
	return insn, nil
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
func FormatAddressDisassembly(dis gapstone.Engine, as w.AddressSpace, va w.VA, numOpcodeBytes uint) (string, uint64, error) {
	insn, e := ReadInstruction(dis, as, va)
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

// GetJumpTarget gets the address to which a known jump instruction
//  transfers control.
// If the instruction is a conditional jump, then this function returns
//  the "jump is taken" target.
func GetJumpTarget(insn gapstone.Instruction) (w.VA, error) {
	// have the following possibilities:
	//   - direct jump: jmp 0x1000
	//   - indirect jump: jmp eax
	//   - indirect jump: jmp [0x1000]???

	if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
		return w.VA(insn.X86.Operands[0].Imm), nil
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_REG {
		panic("TODO: jump OP_REG")
	} else if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
		panic("TODO: jump OP_MEM")
	}
	return w.VA(0), nil
}

// GetJumpTargets gets the possible addresses to which a known jump instruction
//  transfers control.
// For a conditional jump, get both the true and false targets.
// This function uses just the instruction instance, so for an indirect jump, we can't tell much.
func GetJumpTargets(insn gapstone.Instruction) ([]JumpTarget, error) {
	ret := make([]JumpTarget, 0, 2)

	if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic == "jmp" {
		// unconditional jump, have the following possibilities:
		//   - direct jump: jmp 0x1000
		//   - indirect jump: jmp eax
		//   - indirect jump: jmp [0x1000]???

		next, e := GetJumpTarget(insn)
		check(e)
		if e != nil {
			return nil, e
		}
		ret = append(
			ret,
			JumpTarget{
				Va:       next,
				JumpType: JumpTypeUncond,
			})
	} else {
		// assume a two case situation:
		//   here:
		//     jnz yes
		//     xor eax, eax
		//     ret
		//   yes:
		//     mov eax, 1
		//     ret
		falsePc := w.VA(uint64(insn.Address) + uint64(insn.Size))
		truePc, e := GetJumpTarget(insn)
		if e != nil {
			return nil, e
		}

		ret = append(
			ret,
			JumpTarget{
				Va:       truePc,
				JumpType: JumpTypeCondTrue,
			},
			JumpTarget{
				Va:       falsePc,
				JumpType: JumpTypeCondFalse,
			})
	}
	return ret, nil
}

// ExploreBB linearly disassembles instructions starting at a given address
//  in a given address space, invoking the appropriate callbacks, and terminates
//  at the end of the current basic block.
// A basic block is delimited by a ret or jump instruction.
// Returns the addresses to which this basic block may transfer control via jumps.
func (ld *LD) ExploreBB(as w.AddressSpace, va w.VA) ([]w.VA, error) {
	startVa := va
	nextBBs := make([]w.VA, 0, 2)

	isEndOfBB := false
	dis := ld.disassembler
	for insn, e := ReadInstruction(dis, as, va); e == nil && !isEndOfBB; insn, e = ReadInstruction(dis, as, va) {
		for _, fn := range ld.insnHandlers {
			e = fn(insn)
			if e != nil {
				return nil, e
			}
		}

		// stop processing a basic block if we're at: RET, IRET, JUMP
		if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
			break // out of instruction processing loop
		} else if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET) {
			break // out of instruction processing loop
		} else if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) {
			targets, e := GetJumpTargets(insn)
			if e != nil {
				return nil, e
			}

			for _, target := range targets {
				for _, fn := range ld.jumpHandlers {
					e := fn(insn, startVa, target)
					if e != nil {
						return nil, e
					}
				}
				nextBBs = append(nextBBs, target.Va)
			}

			break // out of instruction processing loop
		}

		va = w.VA(uint64(va) + uint64(insn.Size))
	}

	return nextBBs, nil
}

// ExploreFunction linearly disassembles instructions and explores basic
//  blocks starting at a given address in a given address space, invoking
//  appropriate callbacks.
// It terminates once it has explored all the basic blocks it discovers.
func (ld *LD) ExploreFunction(as w.AddressSpace, va w.VA) error {
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
		next, e := ld.ExploreBB(as, bb)
		if e != nil {
			return e
		}

		// push new BB addresses
		lifo = append(lifo, next...)
	}

	return nil
}
