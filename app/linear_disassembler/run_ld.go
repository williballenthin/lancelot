package main

import (
	"debug/pe"
	"fmt"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	AS "github.com/williballenthin/Lancelot/address_space"
	EP "github.com/williballenthin/Lancelot/analysis/file/entry_point"
	Pr "github.com/williballenthin/Lancelot/analysis/file/prologue"
	DCA "github.com/williballenthin/Lancelot/analysis/function/direct_calls"
	N "github.com/williballenthin/Lancelot/analysis/function/name"
	SDA "github.com/williballenthin/Lancelot/analysis/function/stack_delta"
	"github.com/williballenthin/Lancelot/artifacts"
	"github.com/williballenthin/Lancelot/disassembly"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	log_persistence "github.com/williballenthin/Lancelot/persistence/log"
	mem_persistence "github.com/williballenthin/Lancelot/persistence/memory"
	mux_persistence "github.com/williballenthin/Lancelot/persistence/mux"
	"github.com/williballenthin/Lancelot/utils"
	W "github.com/williballenthin/Lancelot/workspace"
	"github.com/williballenthin/Lancelot/workspace/dora/linear_disassembler"
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

	d, e := linear_disassembler.New(ws)
	check(e)

	var lifo []AS.VA

	dis, e := disassembly.New(ws)
	check(e)

	sda, e := SDA.New(ws)
	check(e)

	na, e := N.New(ws)
	check(e)

	dca, e := DCA.New(ws)
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

	ep, e := EP.New(ws)
	check(e)

	pro, e := Pr.New(ws)
	check(e)

	hEp, e := ws.RegisterFileAnalysis(ep)
	check(e)
	defer ws.UnregisterFileAnalysis(hEp)

	hPro, e := ws.RegisterFileAnalysis(pro)
	check(e)
	defer ws.UnregisterFileAnalysis(hPro)

	// callback for drawing instructions nicely
	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		s, _, e := linear_disassembler.FormatAddressDisassembly(
			dis, ws, AS.VA(insn.Address),
			ws.DisplayOptions.NumOpcodeBytes)
		check(e)

		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
				// assume we have: call [0x4010000]  ; IAT
				iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
				sym, e := ws.ResolveAddressToSymbol(iva)
				if e == nil {
					s = s + fmt.Sprintf("  ; %s.%s", sym.ModuleName, sym.SymbolName)
				}
			} else if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
				// assume we have: call 0x401000
				targetva := AS.VA(insn.X86.Operands[0].Imm)
				s = s + fmt.Sprintf("  ; sub_%x", targetva)
			}
		} else if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
				// assume we have: jmp [0x4010000]  ; IAT
				iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
				sym, e := ws.ResolveAddressToSymbol(iva)
				if e == nil {
					s = s + fmt.Sprintf("  ; %s.%s", sym.ModuleName, sym.SymbolName)
				}
			}
		}

		log.Printf(s)
		return nil
	})

	// callback for discovering referenced functions
	// note closure over lifo
	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
				// assume we have: call 0x401000
				targetva := AS.VA(insn.X86.Operands[0].Imm)
				lifo = append(lifo, targetva)
				log.Printf("found function: sub_%s", targetva)
			}
			log.Printf("call: ...")
		}
		return nil
	})

	// callback for computing calling conventions
	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		if !disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
			return nil
		}
		if len(insn.X86.Operands) == 0 {
			log.Printf("calling convention: non-stdcall")
			return nil
		}
		if insn.X86.Operands[0].Type != gapstone.X86_OP_IMM {
			return nil
		}
		stackDelta := insn.X86.Operands[0].Imm
		log.Printf("calling convention: stdcall:0x%x", stackDelta)
		return nil
	})

	// callback for recording intra-function edges
	d.RegisterJumpTraceHandler(func(insn gapstone.Instruction, xref *artifacts.JumpCrossReference) error {
		log.Printf("edge: %s --> %s (%s)", xref.From, xref.To, xref.Type)
		return nil
	})

	// debugging
	check(ws.DumpMemoryRegions())

	log.Printf("============================================")
	log.Printf("ok, thats done. now lets make a function.")

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
