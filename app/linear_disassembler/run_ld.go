package main

import (
	"debug/pe"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/williballenthin/Lancelot/config"
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

	check(config.RegisterDefaultAnalyzers(ws))

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
