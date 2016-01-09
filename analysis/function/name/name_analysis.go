package name_analysis

import (
	"fmt"
	"github.com/williballenthin/Lancelot/artifacts"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type NameAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*NameAnalysis, error) {
	return &NameAnalysis{
		ws: ws,
	}, nil
}

/** NameAnalysis implements FunctionAnalysis interface **/
func (a *NameAnalysis) AnalyzeFunction(f *artifacts.Function) error {
	sym, e := a.ws.ResolveAddressToSymbol(f.Start)
	if e == nil {
		f.SetName(sym.SymbolName)
	} else {
		f.SetName(fmt.Sprintf("sub_%s", f.Start))
	}
	return nil
}
