package direct_calls_analysis

import (
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
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

type DirectCallAnalysis struct {
	// referenced:
	ws *W.Workspace

	// owned:
}

func New(ws *W.Workspace) (*DirectCallAnalysis, error) {
	return &DirectCallAnalysis{
		ws: ws,
	}, nil
}

func (a *DirectCallAnalysis) Close() error {
	return nil
}

/** DirectCallAnalysis implements FunctionAnalysis interface **/
func (a *DirectCallAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	ld, e := LD.New(a.ws)
	check(e)

	c, e := ld.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
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
	defer ld.UnregisterInstructionTraceHandler(c)

	e = ld.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *DirectCallAnalysis) Priority() uint {
	return 50
}
