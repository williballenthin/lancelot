package direct_calls_analysis

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	"github.com/williballenthin/Lancelot/disassembly"
	W "github.com/williballenthin/Lancelot/workspace"
	LD "github.com/williballenthin/Lancelot/workspace/dora/linear_disassembler"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type DirectCallAnalysis struct {
	ws *W.Workspace
	ld *LD.LinearDisassembler
}

func New(ws *W.Workspace) (*DirectCallAnalysis, error) {
	ld, e := LD.New(ws)
	check(e)

	return &DirectCallAnalysis{
		ws: ws,
		ld: ld,
	}, nil
}

/** DirectCallAnalysis implements FunctionAnalysis interface **/
func (a *DirectCallAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	c, e := a.ld.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
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
	defer a.ld.UnregisterInstructionTraceHandler(c)

	e = a.ld.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *DirectCallAnalysis) Priority() uint {
	return 50
}
