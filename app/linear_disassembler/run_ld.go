package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	"github.com/williballenthin/Lancelot/disassembly"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
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

// findAll locates all instances of the given separator in
//  the given byteslice and returns the RVAs relative to the
//  start of the slice.
func findAll(d []byte, sep []byte) ([]AS.RVA, error) {
	var offset uint64
	ret := make([]AS.RVA, 0, 100)
	for {
		i := bytes.Index(d, sep)
		if i == -1 {
			break
		}

		ret = append(ret, AS.RVA(uint64(i)+offset))

		if i+len(sep) > len(d) {
			break
		}
		d = d[i+len(sep):]
		offset += uint64(i + len(sep))
	}
	return ret, nil
}

// findPrologues locates all instances of common x86 function
//   prologues in the given byteslice.
func findPrologues(d []byte) ([]AS.RVA, error) {
	ret := make([]AS.RVA, 0, 100)
	bare := make(map[AS.RVA]bool)

	// first, find prologues with hotpatch region
	hits, e := findAll(d, []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC}) // mov edi, edi; push ebp; mov ebp, esp
	check(e)

	// index the "bare" prologue start for future overlap query
	ret = append(ret, hits...)
	for _, hit := range hits {
		bare[AS.RVA(uint64(hit)+0x2)] = true
	}

	// now, find prologues without hotpatch region
	hits, e = findAll(d, []byte{0x55, 0x8B, 0xEC}) // push ebp; mov ebp, esp
	check(e)

	// and ensure they don't overlap with the hotpatchable prologues
	for _, hit := range hits {
		if _, ok := bare[hit]; ok {
			continue
		}
		ret = append(ret, hit)
	}

	return ret, nil
}

func doit(path string) error {
	f, e := pe.Open(path)
	check(e)

	ws, e := W.New(W.ARCH_X86, W.MODE_32)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	_, e = loader.Load(ws)
	check(e)

	d, e := LinearDisassembler.New(ws)
	check(e)

	var lifo []AS.VA

	dis, e := disassembly.New(ws)
	check(e)

	// callback for drawing instructions nicely
	d.RegisterInstructionTraceHandler(func(insn gapstone.Instruction) error {
		s, _, e := LinearDisassembler.FormatAddressDisassembly(
			dis, ws, AS.VA(insn.Address),
			ws.DisplayOptions.NumOpcodeBytes)
		check(e)

		if disassembly.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			if insn.X86.Operands[0].Type == gapstone.X86_OP_MEM {
				// assume we have: call [0x4010000]  ; IAT
				iva := AS.VA(insn.X86.Operands[0].Mem.Disp)
				sym, e := ws.ResolveImportedFunction(iva)
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
				sym, e := ws.ResolveImportedFunction(iva)
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
				log.Printf("found function: sub_%x", targetva)
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
		log.Printf("edge: 0x%x --> 0x%x (%s)", uint64(xref.From), uint64(xref.To), xref.Type)
		return nil
	})

	// debugging
	check(ws.DumpMemoryRegions())

	// queue up any non-forwarded exports as functions to analyze
	for _, mod := range ws.LoadedModules {
		lifo = append(lifo, mod.EntryPoint)
		for _, export := range mod.ExportsByName {
			if export.IsForwarded {
				continue
			}
			fva := export.RVA.VA(mod.BaseAddress)
			log.Printf("adding function by export (name): 0x%x", fva)
			lifo = append(lifo, fva)
		}
		for _, export := range mod.ExportsByOrdinal {
			if export.IsForwarded {
				continue
			}
			fva := export.RVA.VA(mod.BaseAddress)
			log.Printf("adding function by export (ordinal): 0x%x", fva)
			lifo = append(lifo, fva)
		}
	}

	// search for prologues in each memory region, queue them
	//  up as functions to analyze
	mmaps, e := ws.GetMaps()
	check(e)
	for _, mmap := range mmaps {
		d, e := ws.MemRead(mmap.Address, mmap.Length)
		check(e)

		fns, e := findPrologues(d)
		check(e)

		for _, fn := range fns {
			fva := fn.VA(mmap.Address)
			log.Printf("adding function by prologue signature: 0x%x", fva)
			lifo = append(lifo, fva)
		}
	}

	// here's the main loop. fortunately, its concise.
	// TODO: spawn some goroutines.
	exploredFunctions := make(map[AS.VA]bool)
	for len(lifo) > 0 {
		fva := lifo[len(lifo)-1]
		lifo = lifo[:len(lifo)-1]

		_, exists := exploredFunctions[fva]
		if exists {
			continue
		}

		exploredFunctions[fva] = true
		log.Printf("exploring function: sub_%x", fva)
		e = d.ExploreFunction(ws, fva)
		check(e)
	}

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
