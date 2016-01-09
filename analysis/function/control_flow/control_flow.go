package control_flow_analysis

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	W "github.com/williballenthin/Lancelot/workspace"
	LD "github.com/williballenthin/Lancelot/workspace/dora/linear_disassembler"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type ControlFlowAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*ControlFlowAnalysis, error) {
	return &ControlFlowAnalysis{
		ws: ws,
	}, nil
}

/** ControlFlowAnalysis implements FunctionAnalysis interface **/
func (a *ControlFlowAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	ld, e := LD.New(a.ws)
	check(e)

	c, e := ld.RegisterJumpTraceHandler(func(
		insn gapstone.Instruction,
		from_bb AS.VA,
		target AS.VA,
		jtype artifacts.JumpType) error {

		a.ws.MakeCodeCrossReference(insn.Address, target, jtype)
		return nil
	})
	check(e)
	defer ld.UnregisterInstructionTraceHandler(c)

	e = ld.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *ControlFlowAnalysis) Priority() uint {
	return 50
}
