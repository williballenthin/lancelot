package main

// TODO:
//  - then, forward-emulate one instruction (via code hook) to get next insn

import (
	"bufio"
	"debug/pe"
	"fmt"
	"github.com/codegangsta/cli"
	peloader "github.com/williballenthin/CrystalTiger/loader/pe"
	"github.com/williballenthin/CrystalTiger/utils"
	"github.com/williballenthin/CrystalTiger/workspace"
	"log"
	"os"
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
	line, _, e := bio.ReadLine()
	check(e)
	return string(line), e
}

/*
func (env *peloader.Environment) Emulate(start uint64, end uint64) error {
	/*
		stackAddress := uint64(0x69690000)
		stackSize := uint64(0x4000)
		e := env.u.MemMap(stackAddress-(stackSize/2), stackSize)
		check(e)

		defer func() {
			e := env.u.MemUnmap(stackAddress-(stackSize/2), stackSize)
			check(e)
		}()

		e = env.u.RegWrite(uc.X86_REG_ESP, stackAddress)
		check(e)

		esp, e := env.u.RegRead(uc.X86_REG_ESP)
		check(e)
		fmt.Printf("esp: 0x%x\n", esp)

		env.u.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
			//fmt.Printf("Block: 0x%x, 0x%x\n", addr, size)
		})

		env.u.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
			insn, e := env.DisassembleInstruction(addr)
			check(e)
			fmt.Printf("%s", insn)
		})

		env.u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE,
			func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
				if access == uc.MEM_WRITE {
					fmt.Printf("Mem write")
				} else {
					fmt.Printf("Mem read")
				}
				fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
			})

		invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
		env.u.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
			switch access {
			case uc.MEM_WRITE_UNMAPPED | uc.MEM_WRITE_PROT:
				fmt.Printf("invalid write")
			case uc.MEM_READ_UNMAPPED | uc.MEM_READ_PROT:
				fmt.Printf("invalid read")
			case uc.MEM_FETCH_UNMAPPED | uc.MEM_FETCH_PROT:
				fmt.Printf("invalid fetch")
			default:
				fmt.Printf("unknown memory error")
			}
			fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
			return false
		})

		env.u.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
			rax, _ := mu.RegRead(uc.X86_REG_RAX)
			fmt.Printf("Syscall: %d\n", rax)
		}, uc.X86_INS_SYSCALL)

		done := false
		address := start
		e = env.u.RegWrite(uc.X86_REG_EIP, address)
		check(e)
		for !done {
			fmt.Printf("%08x >", address)
			line, e := getLine()
			check(e)

			insnLength, e := env.GetInstructionLength(address)
			check(e)

			switch line {
			case "q":
				done = true
			case "t":
				e = env.u.Start(address, address+insnLength)
				check(e)
				address, e = env.u.RegRead(uc.X86_REG_EIP)
				check(e)
				break
			case "p":
				e = env.u.Start(address, address+insnLength)
				check(e)
				address, e = env.u.RegRead(uc.X86_REG_EIP)
				check(e)
				break
			case "r":
				eax, e := env.u.RegRead(uc.X86_REG_EAX)
				check(e)
				ebx, e := env.u.RegRead(uc.X86_REG_EBX)
				check(e)
				ecx, e := env.u.RegRead(uc.X86_REG_ECX)
				check(e)
				edx, e := env.u.RegRead(uc.X86_REG_EDX)
				check(e)
				esi, e := env.u.RegRead(uc.X86_REG_ESI)
				check(e)
				edi, e := env.u.RegRead(uc.X86_REG_EDI)
				check(e)
				ebp, e := env.u.RegRead(uc.X86_REG_EBP)
				check(e)
				esp, e := env.u.RegRead(uc.X86_REG_ESP)
				check(e)
				eip, e := env.u.RegRead(uc.X86_REG_EIP)
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
				insn, e := env.DisassembleInstruction(address)
				check(e)
				fmt.Printf(insn)
				break
			}
		}

	return nil
}
*/

func doit(path string) error {
	f, e := pe.Open(path)
	check(e)

	ws, e := workspace.New(workspace.ARCH_X86, workspace.MODE_32)
	check(e)

	loader, e := peloader.New(path, f)
	check(e)

	m, e := loader.Load(ws)
	check(e)

	e = ws.Disassemble(m.EntryPoint, 0x20, os.Stdout)
	check(e)

	emu, e := ws.GetEmulator()
	check(e)

	emu.SetInstructionPointer(m.EntryPoint)

	log.Printf("emudbg: start: 0x%x", emu.GetInstructionPointer())
	e = emu.RunTo(m.EntryPoint + 0x7)
	check(e)
	log.Printf("emudbg: run: 0x%x", emu.GetInstructionPointer())
	e = emu.StepInto()
	check(e)
	log.Printf("emudbg: step into: 0x%x", emu.GetInstructionPointer())

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
