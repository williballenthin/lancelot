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

type JumpType string

var JumpTypeCondTrue JumpType = "jtrue"
var JumpTypeCondFalse JumpType = "jfalse"
var JumpTypeUncond JumpType = "juncond"

type JumpTarget struct {
	Va       w.VA
	JumpType JumpType
}

type InstructionTraceHandler func(va w.VA, insn gapstone.Instruction) error
type JumpTraceHandler func(va w.VA, insn gapstone.Instruction, jump JumpTarget) error

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

// move to utils
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

// move to utils
// return: data at va formatted appropriately, number of bytes for va formatted, error
func FormatAddressDisassembly(dis gapstone.Engine, as w.AddressSpace, va w.VA, numOpcodeBytes uint) (string, uint64, error) {
	insn, e := ReadInstruction(dis, as, va)
	check(e)

	numBytes := uint64(numOpcodeBytes)
	d, e := as.MemRead(va, min(uint64(insn.Size), numBytes))
	check(e)

	// format each of those as hex
	bytesPrefix := make([]string, 0)
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

func (ld *LD) ExploreBB(as w.AddressSpace, va w.VA) ([]w.VA, error) {
	nextBBs := make([]w.VA, 0, 2)

	isEndOfBB := false
	dis := ld.disassembler
	for insn, e := ReadInstruction(dis, as, va); e == nil && !isEndOfBB; insn, e = ReadInstruction(dis, as, va) {
		for _, fn := range ld.insnHandlers {
			e = fn(va, insn)
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
					e := fn(va, insn, target)
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

func (ld *LD) ExploreFunction(as w.AddressSpace, va w.VA) error {
	lifo := make([]w.VA, 0, 10)
	lifo = append(lifo, va)

	doneBBs := map[w.VA]bool{}

	for len(lifo) > 0 {
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

		lifo = append(lifo, next...)
	}

	return nil
}
