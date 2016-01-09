// Package workspace implements an object that tracks
//  analysis configuration, state, and results.
//
// Things it tracks:
//  - configured architecture and mode
//  - loaded binaries
//  - things marked by the analyst
//  - persistent analysis results
//     - xrefs
//     - function, basic block, instruction locations
// TODO: define interfaces for each of the above
package workspace

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	AS "github.com/williballenthin/Lancelot/address_space"
	FA "github.com/williballenthin/Lancelot/analysis/function"
	"github.com/williballenthin/Lancelot/artifacts"
	P "github.com/williballenthin/Lancelot/persistence"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Cookie uint64
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

type DisplayOptions struct {
	NumOpcodeBytes uint
}

type Workspace struct {
	// we cheat and use u as the address space
	as               AS.AddressSpace
	Arch             Arch
	Mode             Mode
	LoadedModules    []*LoadedModule
	DisplayOptions   DisplayOptions
	persistence      P.Persistence
	Artifacts        *artifacts.Artifacts
	functionAnalysis map[Cookie]FA.FunctionAnalysis
	counter          Cookie
}

func New(arch Arch, mode Mode, p P.Persistence) (*Workspace, error) {
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

	arts, e := artifacts.New(p)
	if e != nil {
		return nil, e
	}

	return &Workspace{
		as:            as,
		Arch:          arch,
		Mode:          mode,
		LoadedModules: make([]*LoadedModule, 0),
		DisplayOptions: DisplayOptions{
			NumOpcodeBytes: 8,
		},
		persistence:      p,
		Artifacts:        arts,
		functionAnalysis: make(map[Cookie]FA.FunctionAnalysis),
	}, nil
}

func (ws *Workspace) Close() error {
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

type SymbolResolver interface {
	ResolveAddressToSymbol(va AS.VA) (*LinkedSymbol, error)
}

// Workspace implements SymbolResolver

// perhaps this should be moved into artifacts
func (ws *Workspace) ResolveAddressToSymbol(va AS.VA) (*LinkedSymbol, error) {
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

func (ws *Workspace) RegisterFunctionAnalysis(a FA.FunctionAnalysis) (Cookie, error) {
	ws.counter++
	c := ws.counter
	ws.functionAnalysis[c] = a
	return c, nil
}

func (ws *Workspace) UnregisterFunctionAnalysis(c Cookie) error {
	delete(ws.functionAnalysis, c)
	return nil
}

func (ws *Workspace) MakeFunction(va AS.VA) error {
	_, e := ws.Artifacts.GetFunction(va)
	if e == artifacts.ErrFunctionNotFound {
		f, e := ws.Artifacts.AddFunction(va)
		if e != nil {
			logrus.Warn("error adding function: %s", e.Error())
			return e
		}
		for _, a := range ws.functionAnalysis {
			e := a.AnalyzeFunction(f)
			if e != nil {
				logrus.Warn("function analysis failed: %s", e.Error())
			}
		}
	}
	return e
}
