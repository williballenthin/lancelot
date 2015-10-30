package workspace

// TODO:
//   - AddressSpace interface
//   - RVA type
//   - VA type
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

const ARCH_X86 Arch = "x86"
const MODE_32 Mode = "32"

var GAPSTONE_ARCH_MAP = map[Arch]int{
	ARCH_X86: gapstone.CS_ARCH_X86,
}

var GAPSTONE_MODE_MAP = map[Mode]uint{
	MODE_32: gapstone.CS_MODE_32,
}

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

func (m LoadedModule) MemRead(ws *Workspace, rva uint64, length uint64) ([]byte, error) {
	return ws.u.MemRead(m.VA(rva), length)
}

func (m LoadedModule) MemReadPtr(ws *Workspace, rva uint64) (uint64, error) {
	var data uint32
	d, e := m.MemRead(ws, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return uint64(data), nil
}

func (m LoadedModule) MemWrite(ws *Workspace, rva uint64, data []byte) error {
	return ws.u.MemWrite(m.VA(rva), data)
}

type MemoryRegion struct {
	Address uint64 // VA
	Length  uint64
	Name    string
}

type Workspace struct {
	u             uc.Unicorn
	Arch          Arch
	Mode          Mode
	loadedModules []*LoadedModule
	memoryRegions []MemoryRegion
}

func New(arch Arch, mode Mode) (*Workspace, error) {

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

	return &Workspace{
		u:             u,
		Arch:          arch,
		Mode:          mode,
		loadedModules: make([]*LoadedModule, 1),
		memoryRegions: make([]MemoryRegion, 5),
	}, nil
}

func (ws *Workspace) MemRead(va uint64, length uint64) ([]byte, error) {
	return ws.u.MemRead(va, length)
}

func (ws *Workspace) MemWrite(va uint64, data []byte) error {
	return ws.u.MemWrite(va, data)
}

func (ws *Workspace) MemMap(va uint64, length uint64, name string) error {
	e := ws.u.MemMap(va, length)
	if e != nil {
		return e
	}

	ws.memoryRegions = append(ws.memoryRegions, MemoryRegion{va, length, name})

	return nil
}

func (ws *Workspace) AddLoadedModule(mod *LoadedModule) error {
	ws.loadedModules = append(ws.loadedModules, mod)
	return nil
}

func (ws *Workspace) getDisassembler() (*gapstone.Engine, error) {
	engine, e := gapstone.New(
		GAPSTONE_ARCH_MAP[ws.Arch],
		GAPSTONE_MODE_MAP[ws.Mode],
	)
	return &engine, e
}

func (ws *Workspace) disassembleBytes(data []byte, address uint64, w io.Writer) error {
	// TODO: cache the engine on the Workspace?

	engine, e := ws.getDisassembler()
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

func (ws *Workspace) Disassemble(address uint64, length uint64, w io.Writer) error {
	d, e := ws.u.MemRead(address, length)
	check(e)
	return ws.disassembleBytes(d, address, w)
}

func (ws *Workspace) DisassembleInstruction(address uint64) (string, error) {
	engine, e := ws.getDisassembler()
	check(e)
	defer engine.Close()

	MAX_INSN_SIZE := 0x10
	d, e := ws.u.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := engine.Disasm(d, address, 1)
	check(e)

	for _, insn := range insns {
		return fmt.Sprintf("0x%x: %s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr), nil
	}
	return "", nil
}

func (ws *Workspace) GetInstructionLength(address uint64) (uint64, error) {
	engine, e := ws.getDisassembler()
	check(e)
	defer engine.Close()

	MAX_INSN_SIZE := 0x10
	d, e := ws.u.MemRead(address, uint64(MAX_INSN_SIZE))
	check(e)

	insns, e := engine.Disasm(d, address, 1)
	check(e)

	for _, insn := range insns {
		return uint64(insn.Size), nil
	}
	return 0, nil
}

func (ws *Workspace) Emulate(start uint64, end uint64) error {
	stackAddress := uint64(0x69690000)
	stackSize := uint64(0x4000)
	e := ws.u.MemMap(stackAddress-(stackSize/2), stackSize)
	check(e)

	defer func() {
		e := ws.u.MemUnmap(stackAddress-(stackSize/2), stackSize)
		check(e)
	}()

	e = ws.u.RegWrite(uc.X86_REG_ESP, stackAddress)
	check(e)

	esp, e := ws.u.RegRead(uc.X86_REG_ESP)
	check(e)
	fmt.Printf("esp: 0x%x\n", esp)

	ws.u.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		//fmt.Printf("Block: 0x%x, 0x%x\n", addr, size)
	})

	ws.u.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		insn, e := ws.DisassembleInstruction(addr)
		check(e)
		fmt.Printf("%s", insn)
	})

	ws.u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE,
		func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
			if access == uc.MEM_WRITE {
				fmt.Printf("Mem write")
			} else {
				fmt.Printf("Mem read")
			}
			fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
		})

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	ws.u.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
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

	ws.u.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		fmt.Printf("Syscall: %d\n", rax)
	}, uc.X86_INS_SYSCALL)

	return nil
}
