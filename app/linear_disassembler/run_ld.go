package main

import (
	"debug/pe"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	AS "github.com/williballenthin/Lancelot/address_space"
	file_analysis "github.com/williballenthin/Lancelot/analysis/file"
	entry_point_analysis "github.com/williballenthin/Lancelot/analysis/file/entry_point"
	prologue_analysis "github.com/williballenthin/Lancelot/analysis/file/prologue"
	function_analysis "github.com/williballenthin/Lancelot/analysis/function"
	control_flow_analysis "github.com/williballenthin/Lancelot/analysis/function/control_flow"
	direct_call_analysis "github.com/williballenthin/Lancelot/analysis/function/direct_calls"
	indirect_flow_analysis "github.com/williballenthin/Lancelot/analysis/function/indirect_flow"
	name_analysis "github.com/williballenthin/Lancelot/analysis/function/name"
	stack_delta_analysis "github.com/williballenthin/Lancelot/analysis/function/stack_delta"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	log_persistence "github.com/williballenthin/Lancelot/persistence/log"
	mem_persistence "github.com/williballenthin/Lancelot/persistence/memory"
	mux_persistence "github.com/williballenthin/Lancelot/persistence/mux"
	"github.com/williballenthin/Lancelot/utils"
	W "github.com/williballenthin/Lancelot/workspace"
	"log"
	"os"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to explore",
}

var verboseFlag = cli.BoolFlag{
	Name:  "verbose",
	Usage: "print debugging output",
}

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

	dca, e := direct_call_analysis.New(ws)
	check(e)
	function_analyzers["analysis.function.direct_calls"] = dca

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

func doit(path string) error {
	logrus.SetLevel(logrus.DebugLevel)

	f, e := pe.Open(path)
	check(e)

	memPersis, e := mem_persistence.New()
	check(e)

	logPersis, e := log_persistence.New()
	check(e)

	muxPersis, e := mux_persistence.New(memPersis, logPersis)
	check(e)

	ws, e := W.New(W.ARCH_X86, W.MODE_32, muxPersis)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	function_analyzers, e := getFunctionAnalyzers(ws)
	check(e)
	for name, a := range function_analyzers {
		logrus.Infof("registering: %s", name)
		hA, e := ws.RegisterFunctionAnalysis(a)
		check(e)
		// TODO: is there an issue here of all the closures pointing to the same value?
		defer ws.UnregisterFunctionAnalysis(hA)
	}

	file_analyzers, e := getFileAnalyzers(ws)
	check(e)
	for name, a := range file_analyzers {
		found := false
		// blacklist
		// TODO: make this configurable
		for _, n := range []string{"analysis.file.entry_point", "analysis.file.prologue"} {
			if name == n {
				found = true
				break
			}
		}
		if !found {
			logrus.Infof("registering: %s", name)
			hA, e := ws.RegisterFileAnalysis(a)
			check(e)
			// TODO: is there an issue here of all the closures pointing to the same value?
			defer ws.UnregisterFileAnalysis(hA)
		}
	}

	ws.AnalyzeAll()

	ws.MakeFunction(AS.VA(0x10003c90))

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "run_linear_disassembler"
	app.Usage = "Invoke linear disassembler."
	app.Flags = []cli.Flag{inputFlag}
	app.Action = func(c *cli.Context) {
		if utils.CheckRequiredArgs(c, []cli.StringFlag{inputFlag}) != nil {
			return
		}

		inputFile := c.String("input_file")
		if !utils.DoesPathExist(inputFile) {
			log.Printf("Error: file %s must exist", inputFile)
			return
		}

		check(doit(inputFile))
	}
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
