package workspace

// TODO:
//   - AddressSpace interface
//   - higher level maps api
//     - track allocations
//     - snapshot, revert, commit
//  - then, forward-emulate one instruction (via code hook) to get next insn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Arch string
type Mode string

const ARCH_X86 Arch = "x86"
const MODE_32 Mode = "32"
const MODE_64 Mode = "64"

var GAPSTONE_ARCH_MAP = map[Arch]int{
	ARCH_X86: gapstone.CS_ARCH_X86,
}

var GAPSTONE_MODE_MAP = map[Mode]uint{
	MODE_32: gapstone.CS_MODE_32,
}

var InvalidArchError = errors.New("Invalid ARCH provided.")
var InvalidModeError = errors.New("Invalid MODE provided.")

type LinkedSymbol struct {
	ModuleName string
	SymbolName string
}

type ExportedSymbol struct {
	RVA             AS.RVA
	IsForwarded     bool
	ForwardedSymbol LinkedSymbol
}

type LoadedModule struct {
	Name             string
	BaseAddress      AS.VA
	EntryPoint       AS.VA
	Imports          map[AS.RVA]LinkedSymbol
	ExportsByName    map[string]ExportedSymbol
	ExportsByOrdinal map[uint16]ExportedSymbol
}

func (m LoadedModule) VA(rva AS.RVA) AS.VA {
	return rva.VA(m.BaseAddress)
}

// note: rva is relative to the module
func (m LoadedModule) MemRead(ws *Workspace, rva AS.RVA, length uint64) ([]byte, error) {
	return ws.MemRead(m.VA(rva), length)
}

// note: rva is relative to the module
func (m LoadedModule) MemReadPtr(ws *Workspace, rva AS.RVA) (AS.VA, error) {
	if ws.Mode == MODE_32 {
		var data uint32
		d, e := m.MemRead(ws, rva, 0x4)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return AS.VA(uint64(data)), nil
	} else if ws.Mode == MODE_64 {
		var data uint64
		d, e := m.MemRead(ws, rva, 0x8)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return AS.VA(uint64(data)), nil
	} else {
		return 0, InvalidModeError
	}
}

// note: rva is relative to the module
func (m LoadedModule) MemReadRva(ws *Workspace, rva AS.RVA) (AS.RVA, error) {
	// AS.RVAs are 32bits even on x64
	var data uint32
	d, e := m.MemRead(ws, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return AS.RVA(uint64(data)), nil
}

// MemReadPeOffset reads a 32bit (even on x64) AS.VA from the given address
//  of the module.
// note: rva is relative to the module
func (m LoadedModule) MemReadPeOffset(ws *Workspace, rva AS.RVA) (AS.VA, error) {
	// PE header offsets are 32bits even on x64
	var data uint32
	d, e := m.MemRead(ws, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return AS.VA(uint64(data)), nil
}

// MemReadShort reads a 16bit number (often used for ordinals) from the given
//  address of the module.
// note: rva is relative to the module
func (m LoadedModule) MemReadShort(ws *Workspace, rva AS.RVA) (uint16, error) {
	// PE header offsets are 32bits even on x64
	var data uint16
	d, e := m.MemRead(ws, rva, 0x2)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return data, nil
}

// note: rva is relative to the module
func (m LoadedModule) MemWrite(ws *Workspace, rva AS.RVA, data []byte) error {
	return ws.MemWrite(m.VA(rva), data)
}

type DisplayOptions struct {
	NumOpcodeBytes uint
}

type Workspace struct {
	// we cheat and use u as the address space
	as             AS.AddressSpace
	Arch           Arch
	Mode           Mode
	LoadedModules  []*LoadedModule
	disassembler   gapstone.Engine
	DisplayOptions DisplayOptions
}

func New(arch Arch, mode Mode) (*Workspace, error) {
	if arch != ARCH_X86 {
		return nil, InvalidArchError
	}
	if !(mode == MODE_32 || mode == MODE_64) {
		return nil, InvalidModeError
	}

	as, e := AS.NewSimpleAddressSpace()
	if e != nil {
		return nil, e
	}

	disassembler, e := gapstone.New(
		GAPSTONE_ARCH_MAP[arch],
		GAPSTONE_MODE_MAP[mode],
	)
	if e != nil {
		return nil, e
	}
	e = disassembler.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	check(e)
	if e != nil {
		return nil, e
	}

	return &Workspace{
		as:            as,
		Arch:          arch,
		Mode:          mode,
		LoadedModules: make([]*LoadedModule, 0),
		disassembler:  disassembler,
		DisplayOptions: DisplayOptions{
			NumOpcodeBytes: 8,
		},
	}, nil
}

func (ws *Workspace) Close() error {
	ws.disassembler.Close()
	return nil
}

/** (*Workspace) implements AddressSpace **/

func (ws *Workspace) MemRead(va AS.VA, length uint64) ([]byte, error) {
	return ws.as.MemRead(va, length)
}

func (ws *Workspace) MemWrite(va AS.VA, data []byte) error {
	return ws.as.MemWrite(va, data)
}

func (ws *Workspace) MemMap(va AS.VA, length uint64, name string) error {
	return ws.as.MemMap(va, length, name)
}

func (ws *Workspace) MemUnmap(va AS.VA, length uint64) error {
	return ws.as.MemUnmap(va, length)
}

func (ws *Workspace) GetMaps() ([]AS.MemoryRegion, error) {
	return ws.as.GetMaps()
}

func (ws *Workspace) AddLoadedModule(mod *LoadedModule) error {
	ws.LoadedModules = append(ws.LoadedModules, mod)
	return nil
}

func (ws Workspace) DumpMemoryRegions() error {
	log.Printf("=== memory map ===")
	mmaps, e := ws.GetMaps()
	check(e)
	for _, region := range mmaps {
		log.Printf("  name: %s", region.Name)
		log.Printf("    address: %x", region.Address)
		log.Printf("    length: %x", region.Length)
	}
	return nil
}

var ErrFailedToResolveImport = errors.New("Failed to resolve import")

func (ws *Workspace) ResolveImportedFunction(va AS.VA) (*LinkedSymbol, error) {
	for _, mod := range ws.LoadedModules {
		if va < mod.BaseAddress {
			continue
		}
		rva := AS.RVA(uint64(va) - uint64(mod.BaseAddress))
		sym, ok := mod.Imports[rva]
		if !ok {
			continue
		}
		return &sym, nil
	}

	return nil, ErrFailedToResolveImport
}
