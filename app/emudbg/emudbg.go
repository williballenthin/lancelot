package main

// TODO:
//  - then, forward-emulate one instruction (via code hook) to get next insn

import (
	"bufio"
	"debug/pe"
	"fmt"
	"github.com/anmitsu/go-shlex"
	"github.com/codegangsta/cli"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	peloader "github.com/williballenthin/CrystalTiger/loader/pe"
	"github.com/williballenthin/CrystalTiger/utils"
	"github.com/williballenthin/CrystalTiger/utils/hexdump"
	"github.com/williballenthin/CrystalTiger/workspace"
	"log"
	"os"
	"strconv"
	"strings"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to decode",
}

var outputFlag = cli.StringFlag{
	Name:  "output_file",
	Usage: "where to write decoded data",
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

func getLine() (string, error) {
	bio := bufio.NewReader(os.Stdin)
	// TODO: there might be really long lines here that we should handle
	line, _, e := bio.ReadLine()
	return string(line), e
}

// parse a string containing a hexidecimal number.
// may have prefix '0x', or not
func parseNumber(s string) (uint64, error) {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	return strconv.ParseUint(s, 0x10, 64)
}

func doloop(emu *workspace.Emulator) error {
	done := false
	for !done {
		s, _, e := emu.FormatAddress(emu.GetInstructionPointer())
		check(e)
		fmt.Printf("next:\n" + s)

		fmt.Printf("%08x >", emu.GetInstructionPointer())
		line, e := getLine()
		if e != nil {
			line = ""
			done = true
		}
		words, e := shlex.Split(line, true)
		check(e)
		if e != nil {
			return e
		}
		if len(words) == 0 {
			words = []string{""}
		}

		switch words[0] {
		case "":
			break
		case "q":
			done = true
			break
		case "?", "h", "help":
			fmt.Printf("help:\n")
			fmt.Printf("  q - quit\n")
			fmt.Printf("  ?/h/help - help\n")
			fmt.Printf("  t/stepo - step into\n")
			fmt.Printf("  p/stepi - step over\n")
			fmt.Printf("  r - show register(s)\n")
			fmt.Printf("  u - disassemble\n")
			break
		case "t", "stepi":
			e = emu.StepInto()
			check(e)
			break
		case "p", "stepo":
			e = emu.StepOver()
			check(e)
			break
		case "r":
			eax, e := emu.RegRead(uc.X86_REG_EAX)
			ebx, e := emu.RegRead(uc.X86_REG_EBX)
			ecx, e := emu.RegRead(uc.X86_REG_ECX)
			edx, e := emu.RegRead(uc.X86_REG_EDX)
			esi, e := emu.RegRead(uc.X86_REG_ESI)
			edi, e := emu.RegRead(uc.X86_REG_EDI)
			ebp, e := emu.RegRead(uc.X86_REG_EBP)
			esp, e := emu.RegRead(uc.X86_REG_ESP)
			eip, e := emu.RegRead(uc.X86_REG_EIP)
			check(e)

			fmt.Printf("eax: 0x%08x\n", eax)
			fmt.Printf("ebx: 0x%08x\n", ebx)
			fmt.Printf("ecx: 0x%08x\n", ecx)
			fmt.Printf("edx: 0x%08x\n", edx)
			fmt.Printf("esi: 0x%08x\n", esi)
			fmt.Printf("edi: 0x%08x\n", edi)
			fmt.Printf("ebp: 0x%08x\n", ebp)
			fmt.Printf("esp: 0x%08x\n", esp)
			fmt.Printf("eip: 0x%08x\n", eip)
			// TODO: show flags
			break
		case "u":
			// usage: u [addr|. [length]]
			addr := emu.GetInstructionPointer()
			length := uint64(3)

			if len(words) > 1 {
				// using '.' refers to the current PC value
				if words[1] != "." {
					// otherwise, parse int
					addrInt, e := parseNumber(words[1])
					check(e)
					addr = workspace.VA(addrInt)
				}
			}

			if len(words) > 2 {
				length, e = parseNumber(words[2])
				check(e)
			}

			for i := uint64(0); i < length; i++ {
				s, read, e := emu.FormatAddress(addr)
				check(e)
				fmt.Printf(s)
				addr = workspace.VA(uint64(addr) + read)
			}
			break
		case "dc":
			// usage: dc [addr|. [length]]
			addr := emu.GetInstructionPointer()
			length := uint64(0x40)

			if len(words) > 1 {
				// using '.' refers to the current PC value
				if words[1] != "." {
					// otherwise, parse int
					addrInt, e := parseNumber(words[1])
					check(e)
					addr = workspace.VA(addrInt)
				}
			}

			if len(words) > 2 {
				length, e = parseNumber(words[2])
				check(e)
			}

			b, e := emu.MemRead(addr, length)
			check(e)

			e = hexdump.DumpFromOffset(b, uint64(addr), os.Stdout)
			check(e)

			break
		}
	}

	return nil
}

func doit(path string) error {
	f, e := pe.Open(path)
	check(e)

	ws, e := workspace.New(workspace.ARCH_X86, workspace.MODE_32)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	m, e := loader.Load(ws)
	check(e)

	e = ws.Disassemble(m.EntryPoint, 0x30, os.Stdout)
	check(e)

	emu, e := ws.GetEmulator()
	check(e)

	emu.SetInstructionPointer(m.EntryPoint)

	log.Printf("emudbg: start: 0x%x", emu.GetInstructionPointer())

	//e = emu.RunTo(m.EntryPoint + 0x7)
	e = emu.RunTo(m.EntryPoint + 0xe)
	check(e)
	/*
		log.Printf("emudbg: run: 0x%x", emu.GetInstructionPointer())
		e = emu.StepInto()
		check(e)
		log.Printf("emudbg: step into: 0x%x", emu.GetInstructionPointer())
		e = emu.StepInto()
		check(e)
		log.Printf("emudbg: step into: 0x%x", emu.GetInstructionPointer())
	*/

	e = doloop(emu)
	check(e)

	return nil
}

func doesPathExist(p string) bool {
	_, e := os.Stat(p)
	if e == nil {
		return true
	}
	if os.IsNotExist(e) {
		return false
	}
	return true
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "crystal-tiger-emulator-debugger"
	app.Usage = "Interactively emulate a binary."
	app.Flags = []cli.Flag{inputFlag}
	app.Action = func(c *cli.Context) {
		if utils.CheckRequiredArgs(c, []cli.StringFlag{inputFlag}) != nil {
			return
		}

		inputFile := c.String("input_file")
		if !doesPathExist(inputFile) {
			log.Printf("Error: file %s must exist", inputFile)
			return
		}

		check(doit(inputFile))
	}
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
