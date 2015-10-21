package main

import (
	"bufio"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"log"
	"os"
	"unicode/utf16"
)

var PAGE_SIZE uint64 = 0x1000

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

var RequiredFlagNotProvidedError = errors.New("Required flag not provided.")

func checkRequiredArgs(c *cli.Context, requiredFlags []cli.StringFlag) error {
	for _, flag := range requiredFlags {
		if c.GlobalString(flag.Name) != "" {
			continue
		}
		if c.String(flag.Name) != "" {
			continue
		}
		log.Printf(fmt.Sprintf("Error: '%s' value required", flag.Name))
		return RequiredFlagNotProvidedError
	}
	return nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func roundUp(i uint64, base uint64) uint64 {
	if i%base == 0x0 {
		return i
	} else {
		return i + base - (i % base)
	}
}

func roundUpToPage(i uint64) uint64 {
	return roundUp(i, PAGE_SIZE)
}

type Arch string
type Mode string

var ARCH_X86 Arch = "x86"
var MODE_32 Mode = "32"

var InvalidArchError = errors.New("Invalid ARCH provided.")
var InvalidModeError = errors.New("Invalid MODE provided.")

type LoadedModule struct {
	Name        string
	BaseAddress uint64 // VA (*not* RVA)
	EntryPoint  uint64 // VA (*not* RVA)
}

func (m LoadedModule) VA(rva uint64) uint64 {
	return m.BaseAddress + rva
}

func (m LoadedModule) MemRead(env *Environment, rva uint64, length uint64) ([]byte, error) {
	return env.u.MemRead(m.VA(rva), length)
}

func (m LoadedModule) MemWrite(env *Environment, rva uint64, data []byte) error {
	return env.u.MemWrite(m.VA(rva), data)
}

type MemoryRegion struct {
	Address uint64 // VA
	Length  uint64
}

type Environment struct {
	u             uc.Unicorn
	Arch          Arch
	Mode          Mode
	loadedModules []LoadedModule
	memoryRegions []MemoryRegion
}

func NewEnvironment(arch Arch, mode Mode) (*Environment, error) {

	if arch != ARCH_X86 {
		return nil, InvalidArchError
	}
	if mode != MODE_32 {
		return nil, InvalidModeError
	}

	u, e := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
	if e != nil {
		return nil, e
	}

	return &Environment{
		u:             u,
		Arch:          arch,
		Mode:          mode,
		loadedModules: make([]LoadedModule, 1),
		memoryRegions: make([]MemoryRegion, 5),
	}, nil
}

type ImageImportDirectory struct {
	rvaImportLookupTable  uint32
	TimeDateStamp         uint32
	ForwarderChain        uint32
	rvaModuleName         uint32
	rvaImportAddressTable uint32
}

func (env *Environment) LoadPE(name string, f *pe.File) (*LoadedModule, error) {
	var imageBase uint64
	var addressOfEntryPoint uint64
	var dataDirectory [16]pe.DataDirectory

	if optionalHeader, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		imageBase = uint64(optionalHeader.ImageBase)
		addressOfEntryPoint = uint64(optionalHeader.AddressOfEntryPoint)
		dataDirectory = optionalHeader.DataDirectory
	} else {
		return nil, InvalidModeError
	}

	mod := LoadedModule{
		Name:        name,
		BaseAddress: imageBase,
		EntryPoint:  imageBase + addressOfEntryPoint,
	}

	for _, section := range f.Sections {
		h := section.SectionHeader

		fmt.Printf("section: %s\n", section.SectionHeader.Name)
		fmt.Printf("  virtual address: 0x%x\n", section.SectionHeader.VirtualAddress)
		fmt.Printf("  virtual size: 0x%x\n", section.SectionHeader.VirtualSize)
		fmt.Printf("  file offset: 0x%x\n", section.SectionHeader.Offset)
		fmt.Printf("  file size: 0x%x\n", section.SectionHeader.Size)

		secStart := mod.VA(uint64(h.VirtualAddress))
		secLength := roundUpToPage(uint64(h.VirtualSize))
		e := env.u.MemMap(secStart, secLength)
		check(e)

		d, e := section.Data()
		check(e)

		e = mod.MemWrite(env, uint64(h.VirtualAddress), d)
		check(e)

		region := MemoryRegion{
			Address: secStart,
			Length:  secLength,
		}
		env.memoryRegions = append(env.memoryRegions, region)
	}

	// since we always map at ImageBase, we don't need to apply (32bit) relocs
	// TODO: check 64bit reloc types

	importDirectory := dataDirectory[1]
	importRva := importDirectory.VirtualAddress
	importSize := importDirectory.Size
	fmt.Printf("import rva: 0x%x\n", importRva)
	fmt.Printf("import size: 0x%x\n", importSize)

	// TODO: check ranges
	d, e := mod.MemRead(env, uint64(importDirectory.VirtualAddress), uint64(importDirectory.Size))
	check(e)

	p := bytes.NewBuffer(d)
	for {
		var dir ImageImportDirectory
		binary.Read(p, binary.LittleEndian, &dir.rvaImportLookupTable)
		fmt.Printf("rva import lookup table: 0x%x\n", dir.rvaImportLookupTable)
		if dir.rvaImportLookupTable == 0 {
			break
		}
		binary.Read(p, binary.LittleEndian, &dir.TimeDateStamp)
		fmt.Printf("time date stamp: 0x%x\n", dir.TimeDateStamp)

		binary.Read(p, binary.LittleEndian, &dir.ForwarderChain)
		fmt.Printf("forwarder chain: 0x%x\n", dir.ForwarderChain)

		binary.Read(p, binary.LittleEndian, &dir.rvaModuleName)
		fmt.Printf("rva module name: 0x%x\n", dir.rvaModuleName)

		moduleNameBuf, e := mod.MemRead(env, uint64(dir.rvaModuleName), 0x100)
		check(e)
		moduleName, e := readAscii(moduleNameBuf)
		check(e)

		fmt.Printf("module name: %s\n", string(moduleName))

		binary.Read(p, binary.LittleEndian, &dir.rvaImportAddressTable)
	}

	env.loadedModules = append(env.loadedModules, mod)
	return &mod, nil
}

func readAscii(buf []byte) (string, error) {
	br := bufio.NewReader(bytes.NewReader(buf))
	bytez, e := br.ReadBytes(byte(0x00))
	check(e)
	return string(bytez), nil
}

func readUtf16le(buf []byte) ([]rune, error) {
	start := 0
	end := 0

	for i := 0; i < len(buf)/2; i++ {
		if !(buf[i*2] == 0 && buf[i*2+1] == 0) {
			end = i * 2
			break
		}
	}

	numChars := (end - start) / 2
	d := make([]uint16, numChars)
	for i := 0; i < numChars; i++ {
		d[i] = uint16(buf[i*2]) | (uint16(buf[i*2+1]) << 8)
	}
	return utf16.Decode(d), nil
}

var GAPSTONE_ARCH_MAP = map[Arch]int{
	ARCH_X86: gapstone.CS_ARCH_X86,
}

var GAPSTONE_MODE_MAP = map[Mode]uint{
	MODE_32: gapstone.CS_MODE_32,
}

func (env *Environment) disassembleBytes(data []byte, address uint64, w io.Writer) error {
	// TODO: cache the engine on the Environment?

	engine, e := gapstone.New(
		GAPSTONE_ARCH_MAP[env.Arch],
		GAPSTONE_MODE_MAP[env.Mode],
	)
	check(e)
	defer engine.Close()

	insns, e := engine.Disasm([]byte(data), address, 0 /* all instructions */)
	check(e)

	w.Write([]byte(fmt.Sprintf("Disasm:\n")))
	for _, insn := range insns {
		w.Write([]byte(fmt.Sprintf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)))
	}

	return nil
}

func (env *Environment) Disassemble(address uint64, length uint64, w io.Writer) error {
	d, e := env.u.MemRead(address, length)
	check(e)
	return env.disassembleBytes(d, address, w)
}

func doit(path string) error {
	f, e := pe.Open(path)
	check(e)

	env, e := NewEnvironment(ARCH_X86, MODE_32)
	check(e)

	m, e := env.LoadPE(path, f)
	check(e)

	e = env.Disassemble(m.EntryPoint, 0x20, os.Stdout)
	check(e)

	return nil
}

func main() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "crystal-tiger-pe-loader"
	app.Usage = "Load PE files."
	app.Commands = []cli.Command{
		{
			Name:    "load",
			Aliases: []string{"l"},
			Usage:   "load a pe file",
			Flags:   []cli.Flag{inputFlag, verboseFlag},
			Action: func(c *cli.Context) {
				if checkRequiredArgs(c, []cli.StringFlag{inputFlag}) != nil {
					return
				}
				check(doit(c.String("input_file")))
			},
		},
	}
	app.Run(os.Args)
}
