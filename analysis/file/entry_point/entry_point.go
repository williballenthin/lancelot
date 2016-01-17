package entry_point_analysis

import (
	"github.com/Sirupsen/logrus"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type EntryPointAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*EntryPointAnalysis, error) {
	return &EntryPointAnalysis{
		ws: ws,
	}, nil
}

/** EntryPointAnalysis implements FileAnalysis interface **/
func (a *EntryPointAnalysis) AnalyzeAll() error {
	for _, mod := range a.ws.LoadedModules {
		logrus.Debugf("entry point analysis: found function: module entry: 0x%x", mod.EntryPoint)
		a.ws.MakeFunction(mod.EntryPoint)
		for _, export := range mod.ExportsByName {
			if export.IsForwarded {
				continue
			}
			fva := export.RVA.VA(mod.BaseAddress)
			a.ws.MakeFunction(fva)
			logrus.Debugf("entry point analysis: found function: export: %s", fva)
		}
		for _, export := range mod.ExportsByOrdinal {
			if export.IsForwarded {
				continue
			}
			fva := export.RVA.VA(mod.BaseAddress)
			a.ws.MakeFunction(fva)
			logrus.Debugf("entry point analysis: found function: export: %s", fva)
		}
	}
	return nil
}

func (a *EntryPointAnalysis) Priority() uint {
	return 50
}
