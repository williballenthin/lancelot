package indirect_flow_analysis

import (
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	disassembly "github.com/williballenthin/Lancelot/disassembly"
	ED "github.com/williballenthin/Lancelot/disassembly/emu_disassembler"
	P "github.com/williballenthin/Lancelot/persistence"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type IndirectControlFlowAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*IndirectControlFlowAnalysis, error) {
	return &IndirectControlFlowAnalysis{
		ws: ws,
	}, nil
}

func (a *IndirectControlFlowAnalysis) Close() error {
	return nil
}

func min(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

/** IndirectControlFlowAnalysis implements FunctionAnalysis interface **/
func (a *IndirectControlFlowAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	logrus.Debugf("indirect cf analysis: analyze function: %s", f.Start)
	ed, e := ED.New(a.ws)
	check(e)
	defer ed.Close()

	cj, e := ed.RegisterJumpTraceHandler(func(
		insn gapstone.Instruction,
		from_bb AS.VA,
		target AS.VA,
		jtype P.JumpType) error {

		return a.ws.MakeCodeCrossReference(AS.VA(insn.Address), target, jtype)
	})
	check(e)
	defer ed.UnregisterJumpTraceHandler(cj)

	cb, e := ed.RegisterBBTraceHandler(func(start AS.VA, end AS.VA) error {
		return a.ws.MakeBasicBlock(start, end)
	})
	check(e)
	defer ed.UnregisterBBTraceHandler(cb)

	c, e := ed.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
				// assume we have: call 0x401000
				targetva := AS.VA(insn.X86.Operands[0].Imm)
				a.ws.MakeFunction(targetva)
			}
		}
		return nil
	})
	check(e)
	defer ed.UnregisterInstructionTraceHandler(c)

	e = ed.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *IndirectControlFlowAnalysis) Priority() uint {
	return 75
}
