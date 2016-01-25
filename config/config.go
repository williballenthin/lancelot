package config

import (
	"github.com/williballenthin/Lancelot/persistence"
	log_persistence "github.com/williballenthin/Lancelot/persistence/log"
	mem_persistence "github.com/williballenthin/Lancelot/persistence/memory"
	mux_persistence "github.com/williballenthin/Lancelot/persistence/mux"

	"github.com/Sirupsen/logrus"
	//	AS "github.com/williballenthin/Lancelot/address_space"
	file_analysis "github.com/williballenthin/Lancelot/analysis/file"
	entry_point_analysis "github.com/williballenthin/Lancelot/analysis/file/entry_point"
	prologue_analysis "github.com/williballenthin/Lancelot/analysis/file/prologue"
	function_analysis "github.com/williballenthin/Lancelot/analysis/function"
	control_flow_analysis "github.com/williballenthin/Lancelot/analysis/function/control_flow"
	indirect_flow_analysis "github.com/williballenthin/Lancelot/analysis/function/indirect_flow"
	name_analysis "github.com/williballenthin/Lancelot/analysis/function/name"
	stack_delta_analysis "github.com/williballenthin/Lancelot/analysis/function/stack_delta"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getFunctionAnalyzers(ws *W.Workspace) (map[string]function_analysis.FunctionAnalysis, error) {
	function_analyzers := make(map[string]function_analysis.FunctionAnalysis)

	sda, e := stack_delta_analysis.New(ws)
	check(e)
	function_analyzers["analysis.function.stack_delta"] = sda

	na, e := name_analysis.New(ws)
	check(e)
	function_analyzers["analysis.function.name"] = na

	cf, e := control_flow_analysis.New(ws)
	check(e)
	function_analyzers["analysis.function.control_flow"] = cf

	ifa, e := indirect_flow_analysis.New(ws)
	check(e)
	function_analyzers["analysis.function.indirect_control_flow"] = ifa

	return function_analyzers, nil
}

func getFileAnalyzers(ws *W.Workspace) (map[string]file_analysis.FileAnalysis, error) {
	file_analyzers := make(map[string]file_analysis.FileAnalysis)

	ep, e := entry_point_analysis.New(ws)
	check(e)
	file_analyzers["analysis.file.entry_point"] = ep

	pro, e := prologue_analysis.New(ws)
	check(e)
	file_analyzers["analysis.file.prologue"] = pro

	return file_analyzers, nil
}

func MakeDefaultPersistence() (persistence.Persistence, error) {
	memPersis, e := mem_persistence.New()
	check(e)

	logPersis, e := log_persistence.New()
	check(e)

	muxPersis, e := mux_persistence.New(memPersis, logPersis)
	check(e)

	return muxPersis, nil
}

func RegisterDefaultAnalyzers(ws *W.Workspace) error {
	function_analyzers, e := getFunctionAnalyzers(ws)
	check(e)
	for name, a := range function_analyzers {
		logrus.Infof("registering: %s", name)
		_, e := ws.RegisterFunctionAnalysis(a)
		check(e)
		// we're leaking these guys...
		// defer ws.UnregisterFunctionAnalysis(hA)
	}

	file_analyzers, e := getFileAnalyzers(ws)
	check(e)
	for name, a := range file_analyzers {
		found := false
		// blacklist
		// TODO: make this configurable
		for _, n := range []string{} { //"analysis.file.entry_point", "analysis.file.prologue"} {
			if name == n {
				found = true
				break
			}
		}
		if !found {
			logrus.Infof("registering: %s", name)
			_, e := ws.RegisterFileAnalysis(a)
			check(e)
			// we're leaking these guys...
			// defer ws.UnregisterFileAnalysis(hA)
		}
	}
	return nil
}
