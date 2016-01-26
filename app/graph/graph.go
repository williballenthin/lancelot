package main

import (
	"debug/pe"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	"github.com/williballenthin/Lancelot/config"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	"github.com/williballenthin/Lancelot/utils"
	W "github.com/williballenthin/Lancelot/workspace"
	"log"
	"os"
	"runtime"
	"strconv"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to explore",
}

var fvaFlag = cli.StringFlag{
	Name:  "fva",
	Usage: "address of function to graph",
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

func doit(path string, fva AS.VA) error {
	runtime.LockOSThread()
	logrus.SetLevel(logrus.DebugLevel)

	exe, e := pe.Open(path)
	check(e)

	persis, e := config.MakeDefaultPersistence()
	check(e)

	ws, e := W.New(W.ARCH_X86, W.MODE_32, persis)
	check(e)

	dis, e := ws.GetDisassembler()
	check(e)

	loader, e := peloader.New(path, exe)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	check(config.RegisterDefaultAnalyzers(ws))

	check(ws.MakeFunction(fva))

	f, e := ws.Artifacts.GetFunction(fva)
	check(e)

	fmt.Printf("digraph asm {\n")
	fmt.Printf(" node [shape=plain, style=\"rounded\", fontname=\"courier\"]\n")

	var exploreBBs func(bb *artifacts.BasicBlock) error
	exploreBBs = func(bb *artifacts.BasicBlock) error {
		fmt.Printf("bb_%s [label=<\n", bb.Start)
		fmt.Printf("<TABLE BORDER='1' CELLBORDER='0'>\n")

		insns, e := bb.GetInstructions(dis, ws)
		check(e)
		for _, insn := range insns {
			fmt.Printf("  <TR>\n")
			fmt.Printf("    <TD ALIGN=\"LEFT\">\n")
			fmt.Printf("      %s\n", AS.VA(insn.Address))
			fmt.Printf("    </TD>\n")
			fmt.Printf("    <TD ALIGN=\"LEFT\">\n")
			fmt.Printf("      %s\n", insn.Mnemonic)
			fmt.Printf("    </TD>\n")
			fmt.Printf("    <TD ALIGN=\"LEFT\">\n")
			fmt.Printf("      %s\n", insn.OpStr)
			fmt.Printf("    </TD>\n")
			fmt.Printf("  </TR>\n")
		}
		fmt.Printf("</TABLE>\n")
		fmt.Printf(">];\n")

		nextBBs, e := bb.GetNextBasicBlocks()
		check(e)

		for _, nextBB := range nextBBs {
			exploreBBs(nextBB)
		}

		for _, nextBB := range nextBBs {
			fmt.Printf("bb_%s -> bb_%s;\n", bb.Start, nextBB.Start)
		}

		return nil
	}

	firstBB, e := f.GetFirstBasicBlock()
	check(e)

	exploreBBs(firstBB)
	defer fmt.Printf("}")

	runtime.UnlockOSThread()
	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "run_linear_disassembler"
	app.Usage = "Invoke linear disassembler."
	app.Flags = []cli.Flag{inputFlag, fvaFlag}
	app.Action = func(c *cli.Context) {
		if utils.CheckRequiredArgs(c, []cli.StringFlag{inputFlag, fvaFlag}) != nil {
			return
		}

		inputFile := c.String("input_file")
		if !utils.DoesPathExist(inputFile) {
			log.Printf("Error: file %s must exist", inputFile)
			return
		}

		fva, e := strconv.ParseUint(c.String("fva"), 0x10, 64)
		check(e)

		check(doit(inputFile, AS.VA(fva)))
	}
	app.Run(os.Args)
}
