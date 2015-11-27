package main

import (
	"bufio"
	"debug/pe"
	"errors"
	"fmt"
	"github.com/anmitsu/go-shlex"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	"github.com/fatih/color"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	peloader "github.com/williballenthin/Lancelot/loader/pe"
	"github.com/williballenthin/Lancelot/utils"
	"github.com/williballenthin/Lancelot/utils/hexdump"
	"github.com/williballenthin/Lancelot/workspace"
	"log"
	"os"
	"strconv"
	"strings"
)

var inputFlag = cli.StringFlag{
	Name:  "input_file",
	Usage: "file to emulate",
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

func getRegFromString(s string) (int, error) {
	m := map[string]int{
		"eax": uc.X86_REG_EAX,
		"ebx": uc.X86_REG_EBX,
		"ecx": uc.X86_REG_ECX,
		"edx": uc.X86_REG_EDX,
		"esi": uc.X86_REG_ESI,
		"edi": uc.X86_REG_EDI,
		"ebp": uc.X86_REG_EBP,
		"esp": uc.X86_REG_ESP,
		"eip": uc.X86_REG_EIP,
	}
	r, ok := m[strings.ToLower(s)]
	if !ok {
		return 0, ErrInvalidRegisterName
	}
	return r, nil
}

func getFlagFromString(s string) (int, error) {
	m := map[string]int{
		"cf": workspace.EFLAG_CF,
		"pf": workspace.EFLAG_PF,
		"af": workspace.EFLAG_AF,
		"zf": workspace.EFLAG_ZF,
		"sf": workspace.EFLAG_SF,
		"tf": workspace.EFLAG_TF,
		"if": workspace.EFLAG_IF,
		"df": workspace.EFLAG_DF,
		"of": workspace.EFLAG_OF,
	}
	r, ok := m[strings.ToLower(s)]
	if !ok {
		return 0, ErrInvalidRegisterName
	}
	return r, nil
}

func resolveNumber(emu *workspace.Emulator, s string) (uint64, error) {
	// using '.' refers to the current PC value
	if s == "." {
		return uint64(emu.GetInstructionPointer()), nil
	}

	reg, e := getRegFromString(s)
	if e == nil {
		r, e := emu.RegRead(reg)
		return uint64(r), e
	}
	// otherwise, parse int
	addrInt, e := parseNumber(s)
	check(e)
	return addrInt, nil
}

var ErrInvalidRegisterName = errors.New("Invalid register name")

func IsCF(i gapstone.Instruction) bool {
	if workspace.DoesInstructionHaveGroup(i, gapstone.X86_GRP_JUMP) {
		return true
	}
	if workspace.DoesInstructionHaveGroup(i, gapstone.X86_GRP_CALL) {
		return true
	}
	if workspace.DoesInstructionHaveGroup(i, gapstone.X86_GRP_RET) {
		return true
	}
	return false
}

type EmuDbg struct {
	// TODO: use struct embedding?
	*workspace.Emulator
	snaps []*workspace.Snapshot
}

func New(emu *workspace.Emulator) (*EmuDbg, error) {
	return &EmuDbg{
		Emulator: emu,
		snaps:    make([]*workspace.Snapshot, 0),
	}, nil
}

func GetNextInstruction(emu *EmuDbg) (workspace.VA, error) {
	if len(emu.snaps) > 0 {
		snap := emu.snaps[len(emu.snaps)-1]
		emu.UnhookSnapshot(snap)
	}

	tsnap, e := emu.Snapshot()
	check(e)

	e = emu.StepInto()
	check(e)

	nextPc := emu.GetInstructionPointer()
	e = emu.RestoreSnapshot(tsnap)
	check(e)

	e = emu.UnhookSnapshot(tsnap)
	check(e)

	if len(emu.snaps) > 0 {
		snap := emu.snaps[len(emu.snaps)-1]
		emu.HookSnapshot(snap)
	}
	return nextPc, nil
}

func doloop(emu *workspace.Emulator) error {
	edb, e := New(emu)
	check(e)
	done := false

	app := cli.NewApp()
	app.Name = "cli"
	app.Usage = ""
	app.Commands = []cli.Command{
		{
			Name:    "quit",
			Aliases: []string{"exit", "q"},
			Usage:   "quit the emulator shell",
			//			Subcommands: []cli.Command{},
			Action: func(c *cli.Context) {
				fmt.Printf("quit.\n")
				done = true
			},
		},
		{
			Name:    "help",
			Aliases: []string{"h", "?"},
			Usage:   "show help",
			//			Subcommands: []cli.Command{},
			Action: func(c *cli.Context) {
				if !c.Args().Present() {
					cli.ShowAppHelp(c)
				} else {
					cli.ShowCommandHelp(c, c.Args().First())
				}
			},
		},
		{
			Name:    "stepi",
			Aliases: []string{"t"},
			Usage:   "single step an instruction, emulating into function calls",
			Action: func(c *cli.Context) {
				e := emu.StepInto()
				check(e)
			},
		},
		{
			Name:    "stepo",
			Aliases: []string{"p"},
			Usage:   "single step an instruction, emulating over function calls",
			Action: func(c *cli.Context) {
				e := emu.StepOver()
				check(e)
			},
		},
		{
			Name:    "go",
			Aliases: []string{"g"},
			Usage:   "emulate multiple instructions",
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					addrInt, e := resolveNumber(emu, c.Args().First())
					check(e)
					addr := workspace.VA(addrInt)
					e = emu.RunTo(addr)
					check(e)
				} else {
					fmt.Printf("error: `go` requires one argument\n")
				}
			},
		},

		{
			Name:    "registers",
			Aliases: []string{"reg", "r"},
			Usage:   "show, edit registers",
			Action: func(c *cli.Context) {
				if c.Args().Present() {
					regStr := c.Args().First()
					if strings.Contains(regStr, "=") {
						parts := strings.Split(regStr, "=")
						if len(parts) != 2 {
							fmt.Printf("error: bad register assignment\n")
							return
						}
						regStr := parts[0]
						reg, e := getRegFromString(regStr)
						if e != nil {
							fmt.Printf("error: invalid register name: %s\n", regStr)
							return
						}

						valStr := parts[1]
						val, e := resolveNumber(emu, valStr)
						if e != nil {
							fmt.Printf("error: invalid value: %s\n", valStr)
							return
						}

						e = emu.RegWrite(reg, val)
						check(e)
					} else {
						reg, e := getRegFromString(regStr)
						if e != nil {
							fmt.Printf("error: invalid register name: %s\n", regStr)
							return
						}
						r, e := emu.RegRead(reg)
						check(e)

						fmt.Printf("%s: 0x%08x\n", strings.ToLower(regStr), r)
					}
				} else {
					eax, _ := emu.RegRead(uc.X86_REG_EAX)
					ebx, _ := emu.RegRead(uc.X86_REG_EBX)
					ecx, _ := emu.RegRead(uc.X86_REG_ECX)
					edx, _ := emu.RegRead(uc.X86_REG_EDX)
					esi, _ := emu.RegRead(uc.X86_REG_ESI)
					edi, _ := emu.RegRead(uc.X86_REG_EDI)
					ebp, _ := emu.RegRead(uc.X86_REG_EBP)
					esp, _ := emu.RegRead(uc.X86_REG_ESP)
					eip, _ := emu.RegRead(uc.X86_REG_EIP)
					cf := emu.RegReadEflag(workspace.EFLAG_CF)
					pf := emu.RegReadEflag(workspace.EFLAG_PF)
					af := emu.RegReadEflag(workspace.EFLAG_AF)
					zf := emu.RegReadEflag(workspace.EFLAG_ZF)
					sf := emu.RegReadEflag(workspace.EFLAG_SF)
					tf := emu.RegReadEflag(workspace.EFLAG_TF)
					if_ := emu.RegReadEflag(workspace.EFLAG_IF)
					df := emu.RegReadEflag(workspace.EFLAG_DF)
					of := emu.RegReadEflag(workspace.EFLAG_OF)

					fmt.Printf("eax: 0x%08x  CF: %v\n", eax, cf)
					fmt.Printf("ebx: 0x%08x  PF: %v\n", ebx, pf)
					fmt.Printf("ecx: 0x%08x  AF: %v\n", ecx, af)
					fmt.Printf("edx: 0x%08x  ZF: %v\n", edx, zf)
					fmt.Printf("esi: 0x%08x  SF: %v\n", esi, sf)
					fmt.Printf("edi: 0x%08x  TF: %v\n", edi, tf)
					fmt.Printf("ebp: 0x%08x  IF: %v\n", ebp, if_)
					fmt.Printf("esp: 0x%08x  DF: %v\n", esp, df)
					fmt.Printf("eip: 0x%08x  OF: %v\n", eip, of)
				}
			},
		},
		{
			Name:    "unassemble",
			Aliases: []string{"u", "dis", "disassemble"},
			Usage:   "disassemble instructions",
			Action: func(c *cli.Context) {
				// usage: u [addr|. [num instructions]]
				var e error
				addr := emu.GetInstructionPointer()
				length := uint64(3)

				if c.Args().Get(0) != "" {
					addrInt, e := resolveNumber(emu, c.Args().Get(0))
					check(e)
					addr = workspace.VA(addrInt)
				}

				if c.Args().Get(1) != "" {
					length, e = resolveNumber(emu, c.Args().Get(1))
					check(e)
				}

				for i := uint64(0); i < length; i++ {
					s, read, e := emu.FormatAddress(addr)
					check(e)
					fmt.Printf(s + "\n")
					addr = workspace.VA(uint64(addr) + read)
				}
			},
		},
		{
			Name:    "hexdump",
			Aliases: []string{"dc"},
			Usage:   "disassemble instructions",
			Action: func(c *cli.Context) {
				// usage: dps [addr|. [num bytes]]
				var e error
				addr := emu.GetInstructionPointer()
				length := uint64(0x40)

				if c.Args().Get(1) != "" {
					addrInt, e := resolveNumber(emu, c.Args().Get(1))
					check(e)
					addr = workspace.VA(addrInt)
				}

				if c.Args().Get(2) != "" {
					length, e = resolveNumber(emu, c.Args().Get(2))
					check(e)
				}

				b, e := emu.MemRead(addr, length)
				check(e)

				e = hexdump.DumpFromOffset(b, uint64(addr), os.Stdout)
				check(e)
			},
		},
		{
			Name:    "dps",
			Aliases: []string{},
			Usage:   "dump pointers to symbols",
			Action: func(c *cli.Context) {
				// usage: dps [addr|. [num pointers]]
				var e error
				addr := emu.GetInstructionPointer()
				length := uint64(0x8)

				if c.Args().Get(0) != "" {
					addrInt, e := resolveNumber(emu, c.Args().Get(0))
					check(e)
					addr = workspace.VA(addrInt)
				}

				if c.Args().Get(1) != "" {
					length, e = resolveNumber(emu, c.Args().Get(1))
					check(e)
				}

				for i := uint64(0); i < length; i++ {
					va, e := emu.MemReadPtr(addr)
					check(e)

					fmt.Printf("%08x: %08x\n", uint64(addr), uint64(va))

					if emu.GetMode() == workspace.MODE_32 {
						addr += 0x4
					} else if emu.GetMode() == workspace.MODE_64 {
						addr += 0x8
					}
				}
			},
		},
		{
			Name:    "snapshot",
			Aliases: []string{"s"},
			Usage:   "manipulate snapshots",
			Subcommands: []cli.Command{
				{
					Name:    "create",
					Aliases: []string{"c"},
					Usage:   "create new snapshot",
					Action: func(c *cli.Context) {
						if len(edb.snaps) > 0 {
							// pause the previous current snapshot's memory tracking
							e := emu.UnhookSnapshot(edb.snaps[len(edb.snaps)-1])
							check(e)
						}
						// push our new snapshot onto the stack of snapshots
						snap, e := emu.Snapshot()
						check(e)
						fmt.Printf("Snapshot taken.\n")
						edb.snaps = append(edb.snaps, snap)
					},
				},
				{
					Name:    "revert",
					Aliases: []string{"r"},
					Usage:   "revert to current snapshot",
					Action: func(c *cli.Context) {
						if len(edb.snaps) == 0 {
							fmt.Printf("Error: no snapshot active.\n")
							return
						}

						snap := edb.snaps[len(edb.snaps)-1]
						e := emu.RestoreSnapshot(snap)
						check(e)
						fmt.Printf("Snapshot restored.\n")
					},
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "list snapshots",
					Action: func(c *cli.Context) {
						fmt.Printf("snapshots:\n")
						for i := len(edb.snaps) - 1; i >= 0; i-- {
							snap := edb.snaps[i]
							if i == len(edb.snaps)-1 {
								fmt.Printf("  > %s\n", snap.String())
							} else {
								fmt.Printf("  - %s\n", snap.String())
							}
						}
					},
				},
				{
					Name:    "diff",
					Aliases: []string{"s"},
					Usage:   "diff reg, mem from current snapshot",
					Action: func(c *cli.Context) {
						fmt.Printf("unsupported.\n")
					},
				},
				{
					Name:    "destroy",
					Aliases: []string{"d"},
					Usage:   "destroy current snapshot",
					Action: func(c *cli.Context) {
						if len(edb.snaps) == 0 {
							fmt.Printf("Error: no snapshot active.\n")
						} else {
							// TODO: ensure emu.pc == snap.pc
							snap := edb.snaps[len(edb.snaps)-1]
							e := emu.UnhookSnapshot(snap)
							check(e)
							fmt.Printf("Snapshot destroyed: %s\n", snap.String())

							edb.snaps = edb.snaps[:len(edb.snaps)-1]

							if len(edb.snaps) > 0 {
								oldsnap := edb.snaps[len(edb.snaps)-1]
								e := emu.HookSnapshot(oldsnap)
								// TODO: need to merge changes from `snap` into `oldsnap`
								check(e)
								fmt.Printf("Continuing with snapshot: %s\n", oldsnap.String())
							}
						}
					},
				},
			},
		},
	}

	for !done {

		insn, e := emu.GetCurrentInstruction()
		check(e)

		s, _, e := emu.FormatAddress(emu.GetInstructionPointer())
		check(e)
		color.Set(color.FgHiBlack)
		fmt.Printf("next:\n" + s)

		// hack
		if workspace.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && string(insn.Mnemonic[0]) == "j" {
			nextPc, e := GetNextInstruction(edb)
			check(e)

			if nextPc == workspace.VA(uint64(emu.GetInstructionPointer())+uint64(insn.Size)) {
				fmt.Printf(" (jump not taken)")
			} else {
				fmt.Printf(" (jump taken, to: 0x%08x)", uint64(nextPc))
			}
		}
		fmt.Printf("\n")
		color.Unset()

		color.Set(color.FgBlue)
		fmt.Printf("0x%08x > ", emu.GetInstructionPointer())
		color.Unset()

		// TODO: use a readline like lib here
		line, e := getLine()
		if e != nil {
			line = ""
			done = true
		}

		words, e := shlex.Split("cli "+line, true)
		check(e)
		if e != nil {
			return e
		}
		if len(words) == 1 {
			continue
		}

		app.Run(words)
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

	e = doloop(emu)
	check(e)

	return nil
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
		if !utils.DoesPathExist(inputFile) {
			log.Printf("Error: file %s must exist", inputFile)
			return
		}

		check(doit(inputFile))
	}
	fmt.Printf("%s\n", os.Args)
	app.Run(os.Args)
}
