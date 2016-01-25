package main

import (
	"debug/pe"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	AS "github.com/williballenthin/Lancelot/address_space"
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

	loader, e := peloader.New(path, exe)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	check(config.RegisterDefaultAnalyzers(ws))

	check(ws.MakeFunction(fva))

	f, e := ws.Artifacts.GetFunction(fva)
	check(e)

	fmt.Printf("function:\n")
	fmt.Printf(" va: %s\n", f.Start)
	name, e := f.GetName()
	check(e)
	fmt.Printf(" name: %s\n", name)
	stackDelta, e := f.GetStackDelta()
	check(e)
	fmt.Printf(" stack delta: 0x%x\n", stackDelta)

	firstBB, e := f.GetFirstBasicBlock()
	check(e)
	fmt.Printf("first basic block:\n")
	fmt.Printf("  start: %s\n", firstBB.Start)
	fmt.Printf("  end: %s\n", firstBB.End)
	name, e = firstBB.GetName()
	if e != nil {
		name = fmt.Sprintf("loc_%x", uint64(firstBB.Start))
	}
	fmt.Printf("  name: %s\n", name)

	dis, e := ws.GetDisassembler()
	check(e)

	insns, e := firstBB.GetInstructions(dis, ws)
	check(e)

	for i, insn := range insns {
		fmt.Printf("instruction %d:\n", i)
		fmt.Printf("  address: %s\n", AS.VA(insn.Address))
		fmt.Printf("  mnem: %s\n", insn.Mnemonic)
		fmt.Printf("  line: %s\n", insn.OpStr)
	}

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
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
