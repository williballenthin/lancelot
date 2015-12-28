package main

import (
	"debug/pe"
	"fmt"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	"github.com/williballenthin/Lancelot/utils"
	W "github.com/williballenthin/Lancelot/workspace"
	"github.com/williballenthin/Lancelot/workspace/dora/linear_disassembly"
	"log"
	"os"
	"strconv"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to explore",
}

var fvaFlag = cli.StringFlag{
	Name:  "fva",
	Usage: "address of function to explore (hex)",
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

func doit(path string, fva W.VA) error {
	f, e := pe.Open(path)
	check(e)

	ws, e := W.New(W.ARCH_X86, W.MODE_32)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	d, e := LinearDisassembly.New(ws)
	check(e)

	dis, e := ws.GetDisassembler()
	check(e)

	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		s, _, e := LinearDisassembly.FormatAddressDisassembly(dis, ws, W.VA(insn.Address), ws.DisplayOptions.NumOpcodeBytes)
		check(e)
		if W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
				// assume we have: call [0x4010000]
				iva := W.VA(insn.X86.Operands[0].Mem.Disp)
				sym, e := ws.ResolveImportedFunction(iva)
				if e == nil {
					s = s + fmt.Sprintf("  ; %s.%s", sym.ModuleName, sym.SymbolName)
				}
			}
		}
		log.Printf(s)
		return nil
	})

	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		if W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			//log.Printf("--> call")
		}
		return nil
	})

	d.RegisterJumpTraceHandler(func(insn gapstone.Instruction, bb W.VA, jump LinearDisassembly.JumpTarget) error {
		log.Printf("edge: 0x%x --> 0x%x", uint64(bb), uint64(jump.Va))
		return nil
	})

	e = d.ExploreFunction(ws, fva)
	check(e)

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

		iva, e := strconv.ParseUint(c.String("fva"), 0x10, 64)
		check(e)
		fva := W.VA(iva)
		check(doit(inputFile, fva))
	}
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
