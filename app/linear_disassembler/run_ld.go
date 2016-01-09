package main

import (
	"debug/pe"
	"fmt"
	"github.com/codegangsta/cli"
	entry_point_analysis "github.com/williballenthin/Lancelot/analysis/file/entry_point"
	prologue_analysis "github.com/williballenthin/Lancelot/analysis/file/prologue"
	control_flow_analysis "github.com/williballenthin/Lancelot/analysis/function/control_flow"
	direct_call_analysis "github.com/williballenthin/Lancelot/analysis/function/direct_calls"
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

func doit(path string) error {
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

	sda, e := stack_delta_analysis.New(ws)
	check(e)

	na, e := name_analysis.New(ws)
	check(e)

	dca, e := direct_call_analysis.New(ws)
	check(e)

	cf, e := control_flow_analysis.New(ws)
	check(e)

	hSda, e := ws.RegisterFunctionAnalysis(sda)
	check(e)
	defer ws.UnregisterFunctionAnalysis(hSda)

	hNa, e := ws.RegisterFunctionAnalysis(na)
	check(e)
	defer ws.UnregisterFunctionAnalysis(hNa)

	hDca, e := ws.RegisterFunctionAnalysis(dca)
	check(e)
	defer ws.UnregisterFunctionAnalysis(hDca)

	hCf, e := ws.RegisterFunctionAnalysis(cf)
	check(e)
	defer ws.UnregisterFunctionAnalysis(hCf)

	ep, e := entry_point_analysis.New(ws)
	check(e)

	pro, e := prologue_analysis.New(ws)
	check(e)

	hEp, e := ws.RegisterFileAnalysis(ep)
	check(e)
	defer ws.UnregisterFileAnalysis(hEp)

	hPro, e := ws.RegisterFileAnalysis(pro)
	check(e)
	defer ws.UnregisterFileAnalysis(hPro)

	ws.AnalyzeAll()

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
