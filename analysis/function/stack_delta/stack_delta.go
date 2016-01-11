package stack_delta_analysis

import (
	//	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	"github.com/williballenthin/Lancelot/artifacts"
	"github.com/williballenthin/Lancelot/disassembly"
	LD "github.com/williballenthin/Lancelot/disassembly/linear_disassembler"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type StackDeltaAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*StackDeltaAnalysis, error) {
	return &StackDeltaAnalysis{
		ws: ws,
	}, nil
}

/** StackDeltaAnalysis implements FunctionAnalysis interface **/
func (a *StackDeltaAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	ld, e := LD.New(a.ws)
	check(e)

	didSetStackDelta := false
	c, e := ld.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		if !didSetStackDelta {
			if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
				return nil
			}
			if len(insn.X86.Operands) == 0 {
				f.SetStackDelta(0)
				return nil
			}
			if insn.X86.Operands[0].Type != gapstone.X86_OP_IMM {
				return nil
			}
			stackDelta := insn.X86.Operands[0].Imm
			f.SetStackDelta(stackDelta)
			didSetStackDelta = true
		}
		return nil
	})
	check(e)
	defer ld.UnregisterInstructionTraceHandler(c)

	e = ld.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *StackDeltaAnalysis) Priority() uint {
	return 50
}
