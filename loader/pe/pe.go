package main

import (
	"debug/pe"
	"errors"
	"fmt"
	"github.com/bnagy/gapstone"
	"github.com/codegangsta/cli"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"log"
	"os"
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

func dumpDisassemble32(data []byte, address uint64) error {
	engine, e := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_32,
	)
	check(e)
	defer engine.Close()

	insns, e := engine.Disasm([]byte(data), address, 0 /* all instructions */)
	check(e)

	log.Printf("Disasm:\n")
	for _, insn := range insns {
		log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}

	return nil
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

func Load(f *pe.File, u uc.Unicorn) error {
	var imageBase uint64
	var addressOfEntryPoint uint64

	if optionalHeader, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		fmt.Printf("section alignment: 0x%x\n", optionalHeader.SectionAlignment)
		fmt.Printf("file alignment: 0x%x\n", optionalHeader.FileAlignment)
		imageBase = uint64(optionalHeader.ImageBase)
		addressOfEntryPoint = uint64(optionalHeader.AddressOfEntryPoint)
	}
	if optionalHeader, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		fmt.Printf("section alignment: 0x%x\n", optionalHeader.SectionAlignment)
		fmt.Printf("file alignment: 0x%x\n", optionalHeader.FileAlignment)
		imageBase = optionalHeader.ImageBase
		addressOfEntryPoint = uint64(optionalHeader.AddressOfEntryPoint)
	}

	for _, section := range f.Sections {
		h := section.SectionHeader

		fmt.Printf("section: %s\n", section.SectionHeader.Name)
		fmt.Printf("  virtual address: 0x%x\n", section.SectionHeader.VirtualAddress)
		fmt.Printf("  virtual size: 0x%x\n", section.SectionHeader.VirtualSize)
		fmt.Printf("  file offset: 0x%x\n", section.SectionHeader.Offset)
		fmt.Printf("  file size: 0x%x\n", section.SectionHeader.Size)

		secStart := imageBase + uint64(h.VirtualAddress)
		secLength := roundUpToPage(uint64(h.VirtualSize))
		e := u.MemMap(secStart, secLength)
		check(e)

		d, e := section.Data()
		check(e)

		u.MemWrite(secStart, d)
	}

	// since we always map at ImageBase, we don't need to apply (32bit) relocs
	// TODO: check 64bit reloc types

	fmt.Printf("entry point: 0x%x\n", addressOfEntryPoint)
	fmt.Printf("entry point va : 0x%x\n", imageBase+addressOfEntryPoint)
	d, e := u.MemRead(imageBase+addressOfEntryPoint, 0x20)
	check(e)
	dumpDisassemble32(d, imageBase+addressOfEntryPoint)

	return nil
}

func doit(path string) error {
	f, e := pe.Open(path)
	check(e)

	// TODO: switch based on file type
	u, e := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)

	return Load(f, u)
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
