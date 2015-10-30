package pe

// TODO:
//   - higher level maps api
//     - track allocations
//     - snapshot, revert, commit
//  - then, forward-emulate one instruction (via code hook) to get next insn

import (
	"bufio"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"unicode/utf16"
)

var PAGE_SIZE uint64 = 0x1000

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

func (m LoadedModule) MemReadPtr(env *Environment, rva uint64) (uint64, error) {
	var data uint32
	d, e := m.MemRead(env, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return uint64(data), nil
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
	rvaOriginalThunkTable uint32
	TimeDateStamp         uint32
	ForwarderChain        uint32
	rvaModuleName         uint32
	rvaThunkTable         uint32
}

func (env *Environment) loadPESection(mod *LoadedModule, section *pe.Section) error {
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

	// TODO: apply permissions

	region := MemoryRegion{
		Address: secStart,
		Length:  secLength,
	}
	env.memoryRegions = append(env.memoryRegions, region)

	return nil
}

type ImageImportByName struct {
	Hint uint16
	Name string
}

var FLAG_IMPORT_BY_ORDINAL = 1 << 31

func (env *Environment) resolveThunkTable(mod *LoadedModule, rvaTable uint64) error {
	var offset uint64 = rvaTable
	for {
		rvaImport, e := mod.MemReadPtr(env, offset)
		check(e)

		if rvaImport == 0x0 {
			break
		}

		if rvaImport&uint64(FLAG_IMPORT_BY_ORDINAL) > 0 {
			fmt.Printf("  import by ordinal: %03x\n", rvaImport&uint64(0x7FFFFFFF))
			// TODO: replace thunk with handler
			// notes:
			//    32: PUSH 0xAABBCCDD --> 68 DD CC BB AA
			//        JMP  0xAABBCCDD --> E9 D9 CC BB AA  ugh, relative jump. do a push/ret instead.
			//        RET             --> C3
			//
		} else {
			d, e := mod.MemRead(env, uint64(rvaImport), 0x100)
			check(e)

			p := bytes.NewBuffer(d)
			var importByName ImageImportByName
			binary.Read(p, binary.LittleEndian, &importByName.Hint)

			importByName.Name, e = readAscii(d[2:])
			check(e)

			fmt.Printf("  import by name: %s\n", importByName.Name)
			// TODO: replace thunk with handler
		}

		offset += 4
	}
	return nil
}

func (env *Environment) resolveImports(mod *LoadedModule, dataDirectory [16]pe.DataDirectory) error {
	// since we always map at ImageBase, we don't need to apply (32bit) relocs
	// TODO: check 64bit reloc types

	importDirectory := dataDirectory[1]
	importRva := importDirectory.VirtualAddress
	importSize := importDirectory.Size
	fmt.Printf("import rva: 0x%x\n", importRva)
	fmt.Printf("import size: 0x%x\n", importSize)

	d, e := mod.MemRead(env, uint64(importDirectory.VirtualAddress), uint64(importDirectory.Size))
	check(e)

	p := bytes.NewBuffer(d)
	for {
		var dir ImageImportDirectory
		binary.Read(p, binary.LittleEndian, &dir.rvaOriginalThunkTable)
		fmt.Printf("rva import lookup table: 0x%x\n", dir.rvaOriginalThunkTable)
		if dir.rvaOriginalThunkTable == 0 {
			break
		}
		binary.Read(p, binary.LittleEndian, &dir.TimeDateStamp)
		fmt.Printf("time date stamp: 0x%x\n", dir.TimeDateStamp)

		binary.Read(p, binary.LittleEndian, &dir.ForwarderChain)
		fmt.Printf("forwarder chain: 0x%x\n", dir.ForwarderChain)

		binary.Read(p, binary.LittleEndian, &dir.rvaModuleName)

		moduleNameBuf, e := mod.MemRead(env, uint64(dir.rvaModuleName), 0x100)
		check(e)
		moduleName, e := readAscii(moduleNameBuf)
		check(e)

		fmt.Printf("module name: %s\n", string(moduleName))

		binary.Read(p, binary.LittleEndian, &dir.rvaThunkTable)
		env.resolveThunkTable(mod, uint64(dir.rvaThunkTable))
	}

	return nil
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
		e := env.loadPESection(&mod, section)
		check(e)
	}

	e := env.resolveImports(&mod, dataDirectory)
	check(e)

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

func (env *Environment) getDisassembler() (*gapstone.Engine, error) {
	engine, e := gapstone.New(
		GAPSTONE_ARCH_MAP[env.Arch],
		GAPSTONE_MODE_MAP[env.Mode],
	)
	return &engine, e
}

func (env *Environment) disassembleBytes(data []byte, address uint64, w io.Writer) error {
	// TODO: cache the engine on the Environment?

	engine, e := env.getDisassembler()
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

func (env *Environment) DisassembleInstruction(address uint64) (string, error) {
	engine, e := env.getDisassembler()
	check(e)
	defer engine.Close()

	MAX_INSN_SIZE := 0x10
	d, e := env.u.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := engine.Disasm(d, address, 1)
	check(e)

	for _, insn := range insns {
		return fmt.Sprintf("0x%x: %s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr), nil
	}
	return "", nil
}

func (env *Environment) GetInstructionLength(address uint64) (uint64, error) {
	engine, e := env.getDisassembler()
	check(e)
	defer engine.Close()

	MAX_INSN_SIZE := 0x10
	d, e := env.u.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := engine.Disasm(d, address, 1)
	check(e)

	for _, insn := range insns {
		return uint64(insn.Size), nil
	}
	return 0, nil
}

func (env *Environment) Emulate(start uint64, end uint64) error {
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

	return nil
}
