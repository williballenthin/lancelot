package indirect_flow_analysis

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	ED "github.com/williballenthin/Lancelot/disassembly/emu_disassembler"
	W "github.com/williballenthin/Lancelot/workspace"
	"strings"
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

	ci, e := ed.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {

		// fetch either instruction length, or max configured bytes, amount of data
		numBytes := uint64(a.ws.DisplayOptions.NumOpcodeBytes)
		d, e := a.ws.MemRead(AS.VA(insn.Address), min(uint64(insn.Size), numBytes))
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

		s := fmt.Sprintf("0x%x: %s %s\t%s", insn.Address, prefix, insn.Mnemonic, insn.OpStr)

		logrus.Debugf("IndirectControlFlow: %s", s)

		return nil
	})
	check(e)
	defer ed.UnregisterInstructionTraceHandler(ci)

	e = ed.ExploreFunction(a.ws, f.Start)
	check(e)

	return nil
}

func (a *IndirectControlFlowAnalysis) Priority() uint {
	return 75
}
