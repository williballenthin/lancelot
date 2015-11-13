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
	"fmt"
	"github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

const MAX_INSN_SIZE = 0x10

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

type VA uint64
type RVA uint64

func (rva RVA) VA(baseAddress VA) VA {
	return VA(uint64(rva) + uint64(baseAddress))
}

type LoadedModule struct {
	Name        string
	BaseAddress VA
	EntryPoint  VA
}

func (m LoadedModule) VA(rva RVA) VA {
	return rva.VA(m.BaseAddress)
}

// note: relative to the module
func (m LoadedModule) MemRead(ws *Workspace, rva RVA, length uint64) ([]byte, error) {
	return ws.MemRead(m.VA(rva), length)
}

// note: relative to the module
func (m LoadedModule) MemReadPtr(ws *Workspace, rva RVA) (VA, error) {
	if ws.Mode == MODE_32 {
		var data uint32
		d, e := m.MemRead(ws, rva, 0x4)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return VA(uint64(data)), nil
	} else if ws.Mode == MODE_64 {
		var data uint64
		d, e := m.MemRead(ws, rva, 0x8)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return VA(uint64(data)), nil
	} else {
		return 0, InvalidModeError
	}
}

// note: relative to the module
func (m LoadedModule) MemWrite(ws *Workspace, rva RVA, data []byte) error {
	return ws.MemWrite(m.VA(rva), data)
}

type MemoryRegion struct {
	Address VA
	Length  uint64
	Name    string
}

type AddressSpace interface {
	MemRead(va VA, length uint64) ([]byte, error)
	MemWrite(va VA, data []byte) error
	MemMap(va VA, length uint64, name string) error
	MemUnmap(va VA, length uint64) error
}

type Workspace struct {
	// we cheat and use u as the address space
	u             uc.Unicorn
	Arch          Arch
	Mode          Mode
	loadedModules []*LoadedModule
	memoryRegions []MemoryRegion
	disassembler  gapstone.Engine
}

func New(arch Arch, mode Mode) (*Workspace, error) {
	if arch != ARCH_X86 {
		return nil, InvalidArchError
	}
	// TODO: pick mode
	if !(mode == MODE_32 || mode == MODE_64) {
		return nil, InvalidModeError
	}

	u, e := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
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
		u:             u,
		Arch:          arch,
		Mode:          mode,
		loadedModules: make([]*LoadedModule, 0),
		memoryRegions: make([]MemoryRegion, 0),
		disassembler:  disassembler,
	}, nil
}

func (ws *Workspace) Close() error {
	ws.disassembler.Close()
	return nil
}

func (ws *Workspace) MemRead(va VA, length uint64) ([]byte, error) {
	return ws.u.MemRead(uint64(va), length)
}

func (ws *Workspace) MemWrite(va VA, data []byte) error {
	return ws.u.MemWrite(uint64(va), data)
}

func (ws *Workspace) MemMap(va VA, length uint64, name string) error {
	e := ws.u.MemMap(uint64(va), length)
	if e != nil {
		return e
	}

	ws.memoryRegions = append(ws.memoryRegions, MemoryRegion{va, length, name})

	return nil
}

var InvalidArgumentError = errors.New("Invalid argument")

func (ws *Workspace) MemUnmap(va VA, length uint64) error {
	e := ws.u.MemUnmap(uint64(va), length)
	if e != nil {
		return e
	}

	for i, region := range ws.memoryRegions {
		if region.Address == va {
			if region.Length != length {
				return InvalidArgumentError
			}

			ws.memoryRegions = append(ws.memoryRegions[:i], ws.memoryRegions[i+1:]...)
			break
		}
	}

	return nil
}

func (ws *Workspace) AddLoadedModule(mod *LoadedModule) error {
	ws.loadedModules = append(ws.loadedModules, mod)
	return nil
}

// TODO: remove this?
func (ws *Workspace) disassembleBytes(data []byte, address VA, w io.Writer) error {
	insns, e := ws.disassembler.Disasm([]byte(data), uint64(address), 0 /* all instructions */)
	check(e)

	w.Write([]byte(fmt.Sprintf("Disasm:\n")))
	for _, insn := range insns {
		w.Write([]byte(fmt.Sprintf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)))
	}

	return nil
}

// TODO: remove this?
func (ws *Workspace) Disassemble(address VA, length uint64, w io.Writer) error {
	d, e := ws.MemRead(address, length)
	check(e)
	return ws.disassembleBytes(d, address, w)
}

// TODO: remove this?
var FailedToDisassembleInstruction = errors.New("Failed to disassemble an instruction")

// TODO: remove this?
func (ws *Workspace) DisassembleInstruction(address VA) (string, error) {
	d, e := ws.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := ws.disassembler.Disasm(d, uint64(address), 1)
	check(e)

	for _, insn := range insns {
		// return the first one
		return fmt.Sprintf("0x%x: %s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr), nil
	}
	return "", FailedToDisassembleInstruction
}

func (ws *Workspace) GetInstructionLength(address VA) (uint64, error) {
	d, e := ws.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := ws.disassembler.Disasm(d, uint64(address), 1)
	check(e)

	for _, insn := range insns {
		// return the first one
		return uint64(insn.Size), nil
	}
	return 0, FailedToDisassembleInstruction
}

type Emulator struct {
	ws            *Workspace
	u             uc.Unicorn
	disassembler  gapstone.Engine
	memoryRegions []MemoryRegion
}

func newEmulator(ws *Workspace) (*Emulator, error) {
	if ws.Arch != ARCH_X86 {
		return nil, InvalidArchError
	}
	if !(ws.Mode == MODE_32 || ws.Mode == MODE_64) {
		return nil, InvalidModeError
	}

	// TODO: pick mode
	u, e := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
	if e != nil {
		return nil, e
	}

	disassembler, e := gapstone.New(
		GAPSTONE_ARCH_MAP[ws.Arch],
		GAPSTONE_MODE_MAP[ws.Mode],
	)
	if e != nil {
		return nil, e
	}

	return &Emulator{
		ws:            ws,
		u:             u,
		disassembler:  disassembler,
		memoryRegions: make([]MemoryRegion, 0),
	}, nil
}

func (emu *Emulator) Close() error {
	emu.disassembler.Close()
	return nil
}

func (emu *Emulator) MemRead(va VA, length uint64) ([]byte, error) {
	return emu.u.MemRead(uint64(va), length)
}

func (emu *Emulator) MemWrite(va VA, data []byte) error {
	return emu.u.MemWrite(uint64(va), data)
}

func (emu *Emulator) MemMap(va VA, length uint64, name string) error {
	e := emu.u.MemMap(uint64(va), length)
	if e != nil {
		return e
	}

	emu.memoryRegions = append(emu.memoryRegions, MemoryRegion{va, length, name})

	return nil
}

func (emu *Emulator) MemUnmap(va VA, length uint64) error {
	e := emu.u.MemUnmap(uint64(va), length)
	if e != nil {
		return e
	}

	for i, region := range emu.memoryRegions {
		if region.Address == va {
			if region.Length != length {
				return InvalidArgumentError
			}

			emu.memoryRegions = append(emu.memoryRegions[:i], emu.memoryRegions[i+1:]...)
			break
		}
	}

	return nil
}

func (ws Workspace) dumpMemoryRegions() error {
	log.Printf("=== memory map ===")
	for _, region := range ws.memoryRegions {
		log.Printf("  name: %s", region.Name)
		log.Printf("    address: %x", region.Address)
		log.Printf("    length: %x", region.Length)
	}
	return nil
}

func (ws *Workspace) GetEmulator() (*Emulator, error) {
	emu, e := newEmulator(ws)
	if e != nil {
		return nil, e
	}

	for _, region := range ws.memoryRegions {
		e := emu.MemMap(region.Address, region.Length, region.Name)
		check(e)
		if e != nil {
			emu.Close()
			return nil, e
		}

		d, e := ws.MemRead(region.Address, region.Length)
		check(e)
		if e != nil {
			emu.Close()
			return nil, e
		}

		e = emu.MemWrite(region.Address, d)
		check(e)
		if e != nil {
			emu.Close()
			return nil, e
		}
	}

	stackAddress := VA(0x69690000)
	stackSize := uint64(0x40000)
	e = emu.MemMap(VA(uint64(stackAddress)-(stackSize/2)), stackSize, "stack")
	check(e)

	emu.SetStackPointer(stackAddress)

	return emu, nil
}

func (emu *Emulator) RegRead(reg int) (uint64, error) {
	return emu.u.RegRead(reg)
}

func (emu *Emulator) RegWrite(reg int, value uint64) error {
	return emu.u.RegWrite(reg, value)
}

func (emu *Emulator) SetStackPointer(address VA) {
	if emu.ws.Arch == ARCH_X86 {
		if emu.ws.Mode == MODE_32 {
			emu.RegWrite(uc.X86_REG_ESP, uint64(address))
			return
		} else if emu.ws.Mode == MODE_64 {
			emu.RegWrite(uc.X86_REG_RSP, uint64(address))
			return
		} else {
			panic(InvalidModeError)
		}
	} else {
		panic(InvalidArchError)
	}
}

func (emu *Emulator) GetStackPointer() VA {
	var r uint64
	var e error
	if emu.ws.Arch == ARCH_X86 {
		if emu.ws.Mode == MODE_32 {
			r, e = emu.RegRead(uc.X86_REG_ESP)
		} else if emu.ws.Mode == MODE_64 {
			r, e = emu.RegRead(uc.X86_REG_RSP)
		} else {
			panic(InvalidModeError)
		}
	} else {
		panic(InvalidArchError)
	}
	if e != nil {
		panic(e)
	}
	return VA(r)
}

func (emu *Emulator) SetInstructionPointer(address VA) {
	if emu.ws.Arch == ARCH_X86 {
		if emu.ws.Mode == MODE_32 {
			emu.RegWrite(uc.X86_REG_EIP, uint64(address))
			return
		} else if emu.ws.Mode == MODE_64 {
			emu.RegWrite(uc.X86_REG_RIP, uint64(address))
			return
		} else {
			panic(InvalidModeError)
		}
	} else {
		panic(InvalidArchError)
	}
}

func (emu *Emulator) GetInstructionPointer() VA {
	var r uint64
	var e error
	if emu.ws.Arch == ARCH_X86 {
		if emu.ws.Mode == MODE_32 {
			r, e = emu.RegRead(uc.X86_REG_EIP)
		} else if emu.ws.Mode == MODE_64 {
			r, e = emu.RegRead(uc.X86_REG_RIP)
		} else {
			panic(InvalidModeError)
		}
	} else {
		panic(InvalidArchError)
	}
	if e != nil {
		panic(e)
	}
	return VA(r)
}

// utility method for handling the uint64 casting
func (emu *Emulator) start(begin VA, until VA) error {
	return emu.u.Start(uint64(begin), uint64(until))
}

var InvalidMemoryWriteError error = errors.New("Invalid memory write error")
var InvalidMemoryReadError error = errors.New("Invalid memory read error")
var InvalidMemoryExecError error = errors.New("Invalid memory exec error")
var UnknownMemoryError error = errors.New("Unknown memory error")

func (emu *Emulator) removeHook(h uc.Hook) error {
	//log.Printf("DEBUG: remove hook: %v", h)
	e := emu.u.HookDel(h)
	check(e)
	return e
}

type CloseableHook struct {
	emu *Emulator
	h   uc.Hook
}

func (hook *CloseableHook) Close() error {
	return hook.emu.removeHook(hook.h)
}

func (emu *Emulator) hookInvalidMemory(err *error) (*CloseableHook, error) {
	h, e := emu.u.HookAdd(
		uc.HOOK_MEM_READ_INVALID|uc.HOOK_MEM_WRITE_INVALID|uc.HOOK_MEM_FETCH_INVALID,
		func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {

			switch access {
			case uc.MEM_WRITE_UNMAPPED | uc.MEM_WRITE_PROT:
				log.Printf("WARN: invalid write")
				*err = InvalidMemoryWriteError
			case uc.MEM_READ_UNMAPPED | uc.MEM_READ_PROT:
				log.Printf("WARN: invalid read")
				*err = InvalidMemoryReadError
			case uc.MEM_FETCH_UNMAPPED | uc.MEM_FETCH_PROT:
				log.Printf("WARN: invalid fetch")
				*err = InvalidMemoryExecError
			default:
				log.Printf("WARN: unknown memory error")
				*err = UnknownMemoryError
			}
			log.Printf("WARN: @0x%x [0x%x] = 0x%x\n", addr, size, value)

			emu.u.Stop()

			return false
		})

	check(e)
	if e != nil {
		return nil, e
	}

	return &CloseableHook{emu: emu, h: h}, nil
}

func (emu *Emulator) RunTo(address VA) error {
	ip := emu.GetInstructionPointer()

	var memErr error = nil
	memHook, e := emu.hookInvalidMemory(&memErr)
	check(e)
	defer memHook.Close()

	e = emu.start(ip, address)
	check(e)
	if e != nil {
		return e
	}
	check(memErr)
	if memErr != nil {
		return memErr
	}

	return nil
}

var EmulatorEscapedError = errors.New("Emulator failed to stop as requested.")

func (emu *Emulator) StepInto() error {
	var memErr error = nil
	var codeErr error = nil

	//log.Printf("DEBUG: step into")

	memHook, e := emu.hookInvalidMemory(&memErr)
	check(e)
	defer memHook.Close()

	// always stop after one instruction
	hitCount := 0
	h, e := emu.u.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		if hitCount == 0 {
			// pass
		} else if hitCount == 1 {
			emu.u.Stop()
		} else {
			codeErr = EmulatorEscapedError
		}
		hitCount += 1
	})
	check(e)
	defer emu.removeHook(h)

	insn, e := emu.GetCurrentInstruction()
	ip := emu.GetInstructionPointer()
	end := VA(uint64(ip) + uint64(insn.Size))
	e = emu.start(ip, end)
	check(e)
	if e != nil {
		return e
	}
	check(memErr)
	if memErr != nil {
		return memErr
	}
	check(codeErr)
	if codeErr != nil {
		return codeErr
	}

	return nil
}

func (emu *Emulator) GetCurrentInstruction() (gapstone.Instruction, error) {
	ip := emu.GetInstructionPointer()

	d, e := emu.MemRead(ip, uint64(MAX_INSN_SIZE))
	check(e)
	if e != nil {
		return gapstone.Instruction{}, InvalidMemoryReadError
	}

	insns, e := emu.disassembler.Disasm(d, uint64(ip), 1)
	check(e)
	if e != nil {
		return gapstone.Instruction{}, FailedToDisassembleInstruction
	}

	if len(insns) == 0 {
		return gapstone.Instruction{}, FailedToDisassembleInstruction
	}

	insn := insns[0]
	return insn, nil
}

func DoesInstructionHaveGroup(i gapstone.Instruction, group uint) bool {
	for _, group := range i.Groups {
		if group == group {
			return true
		}
	}
	return false
}

func (emu *Emulator) StepOver() error {
	insn, e := emu.GetCurrentInstruction()
	check(e)
	if e != nil {
		return e
	}

	if DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
		return emu.RunTo(VA(uint64(emu.GetInstructionPointer()) + uint64(insn.Size)))
	} else {
		return emu.StepInto()
	}
}
