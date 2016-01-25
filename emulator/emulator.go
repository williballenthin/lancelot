package emulator

import (
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	AS "github.com/williballenthin/Lancelot/address_space"
	dis "github.com/williballenthin/Lancelot/disassembly"
	W "github.com/williballenthin/Lancelot/workspace"
	"runtime"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Emulator struct {
	// reference:
	ws *W.Workspace

	// own:
	u            uc.Unicorn
	disassembler *gapstone.Engine
	maps         []AS.MemoryRegion
	hooks        struct {
		memRead     *hookMultiplexer
		memWrite    *hookMultiplexer
		memUnmapped *hookMultiplexer
		code        *hookMultiplexer
	}
}

func New(ws *W.Workspace) (*Emulator, error) {
	logrus.Debug("emulator: new")
	if ws.Arch != W.ARCH_X86 {
		return nil, W.InvalidArchError
	}
	if !(ws.Mode == W.MODE_32 || ws.Mode == W.MODE_64) {
		return nil, W.InvalidModeError
	}

	runtime.LockOSThread()
	var u uc.Unicorn
	var e error
	if ws.Mode == W.MODE_32 {
		u, e = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
	} else if ws.Mode == W.MODE_64 {
		u, e = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
	}
	if e != nil {
		return nil, e
	}

	disassembler, e := gapstone.New(
		W.GAPSTONE_ARCH_MAP[ws.Arch],
		W.GAPSTONE_MODE_MAP[ws.Mode],
	)
	if e != nil {
		return nil, e
	}
	e = disassembler.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	check(e)
	if e != nil {
		return nil, e
	}

	emu := &Emulator{
		ws:           ws,
		u:            u,
		disassembler: &disassembler,
		maps:         make([]AS.MemoryRegion, 0),
	}

	e = AS.CopyAddressSpace(emu, ws)
	check(e)
	if e != nil {
		return nil, e
	}

	stackAddress := AS.VA(0x69690000)
	stackSize := uint64(0x40000)
	e = emu.MemMap(AS.VA(uint64(stackAddress)-(stackSize/2)), stackSize, "stack")
	check(e)

	emu.SetStackPointer(stackAddress)

	return emu, nil
}

func (emu *Emulator) Close() error {
	logrus.Debug("emulator: close")
	if emu.hooks.memRead != nil {
		emu.hooks.memRead.Close()
	}
	if emu.hooks.memWrite != nil {
		emu.hooks.memWrite.Close()
	}
	if emu.hooks.memUnmapped != nil {
		emu.hooks.memUnmapped.Close()
	}
	if emu.hooks.code != nil {
		emu.hooks.code.Close()
	}
	emu.disassembler.Close()
	emu.u.Close()
	runtime.UnlockOSThread()
	return nil
}

/** (*Emulator) implements AddressSpace **/

func (emu *Emulator) MemRead(va AS.VA, length uint64) ([]byte, error) {
	logrus.Debugf("emulator: mem read: %s 0x%x", va, length)
	return emu.u.MemRead(uint64(va), length)
}

func (emu *Emulator) MemWrite(va AS.VA, data []byte) error {
	logrus.Debugf("emulator: mem write: %s 0x%x", va, len(data))
	return emu.u.MemWrite(uint64(va), data)
}

func (emu *Emulator) MemMap(va AS.VA, length uint64, name string) error {
	logrus.Debugf("emulator: mem map: %s 0x%x %s", va, length, name)
	e := emu.u.MemMap(uint64(va), length)
	if e != nil {
		return e
	}

	emu.maps = append(emu.maps, AS.MemoryRegion{va, length, name})

	return nil
}

func (emu *Emulator) MemUnmap(va AS.VA, length uint64) error {
	logrus.Debugf("emulator: mem unmap: %s 0x%x", va, length)
	e := emu.u.MemUnmap(uint64(va), length)
	if e != nil {
		return e
	}

	for i, region := range emu.maps {
		if region.Address == va {
			if region.Length != length {
				return AS.InvalidArgumentError
			}

			emu.maps = append(emu.maps[:i], emu.maps[i+1:]...)
			break
		}
	}

	return nil
}

func (emu *Emulator) GetMaps() ([]AS.MemoryRegion, error) {
	ret := make([]AS.MemoryRegion, len(emu.maps))
	copy(ret, emu.maps)
	return ret, nil
}

// read a pointer-sized number from the given address
func (emu *Emulator) MemReadPtr(va AS.VA) (AS.VA, error) {
	return W.MemReadPointer(emu, va, emu.ws.Mode)
}

func (emu Emulator) GetMode() W.Mode {
	return emu.ws.Mode
}
func (emu *Emulator) RegRead(reg int) (uint64, error) {
	logrus.Debug("emulator: regread")
	return emu.u.RegRead(reg)
}

const EFLAG_CF = 1 << 0
const EFLAG_R1 = 1 << 1
const EFLAG_PF = 1 << 2
const EFLAG_R3 = 1 << 3
const EFLAG_AF = 1 << 4
const EFLAG_R5 = 1 << 5
const EFLAG_ZF = 1 << 6
const EFLAG_SF = 1 << 7
const EFLAG_TF = 1 << 8
const EFLAG_IF = 1 << 9
const EFLAG_DF = 1 << 10
const EFLAG_OF = 1 << 11
const EFLAG_IOPL0 = 1 << 12
const EFLAG_IOPL1 = 1 << 13
const EFLAG_NT = 1 << 14
const EFLAG_R16 = 1 << 15
const EFLAG_RF = 1 << 16
const EFLAG_VM = 1 << 17
const EFLAG_AC = 1 << 18
const EFLAG_VIF = 1 << 19
const EFLAG_VIP = 1 << 20
const EFLAG_ID = 1 << 21

func (emu *Emulator) RegReadEflag(eflag uint64) bool {
	if v, _ := emu.RegRead(uc.X86_REG_EFLAGS); v&eflag > 0 {
		return true
	} else {
		return false
	}
}

func (emu *Emulator) RegWrite(reg int, value uint64) error {
	logrus.Debug("emulator: reg write")
	return emu.u.RegWrite(reg, value)
}

func (emu *Emulator) RegSetEflag(eflag uint64) {
	v, _ := emu.RegRead(uc.X86_REG_EFLAGS)
	v |= eflag
	emu.RegWrite(uc.X86_REG_EFLAGS, v)
}

func (emu *Emulator) RegUnsetEflag(eflag uint64) {
	v, _ := emu.RegRead(uc.X86_REG_EFLAGS)
	v &^= (eflag)
	emu.RegWrite(uc.X86_REG_EFLAGS, v)
}

func (emu *Emulator) RegToggleEflag(eflag uint64) {
	if emu.RegReadEflag(eflag) {
		emu.RegUnsetEflag(eflag)
	} else {
		emu.RegSetEflag(eflag)
	}
}

func (emu *Emulator) SetStackPointer(address AS.VA) {
	logrus.Debug("emulator: set stack pointer")
	if emu.ws.Arch == W.ARCH_X86 {
		if emu.ws.Mode == W.MODE_32 {
			emu.RegWrite(uc.X86_REG_ESP, uint64(address))
			return
		} else if emu.ws.Mode == W.MODE_64 {
			emu.RegWrite(uc.X86_REG_RSP, uint64(address))
			return
		} else {
			panic(W.InvalidModeError)
		}
	} else {
		panic(W.InvalidArchError)
	}
}

func (emu *Emulator) GetStackPointer() AS.VA {
	logrus.Debug("emulator: get stack pointer")
	var r uint64
	var e error
	if emu.ws.Arch == W.ARCH_X86 {
		if emu.ws.Mode == W.MODE_32 {
			r, e = emu.RegRead(uc.X86_REG_ESP)
		} else if emu.ws.Mode == W.MODE_64 {
			r, e = emu.RegRead(uc.X86_REG_RSP)
		} else {
			panic(W.InvalidModeError)
		}
	} else {
		panic(W.InvalidArchError)
	}
	if e != nil {
		panic(e)
	}
	return AS.VA(r)
}

func (emu *Emulator) SetInstructionPointer(address AS.VA) {
	logrus.Debug("emulator: set insn pointer")
	if emu.ws.Arch == W.ARCH_X86 {
		if emu.ws.Mode == W.MODE_32 {
			emu.RegWrite(uc.X86_REG_EIP, uint64(address))
			return
		} else if emu.ws.Mode == W.MODE_64 {
			emu.RegWrite(uc.X86_REG_RIP, uint64(address))
			return
		} else {
			panic(W.InvalidModeError)
		}
	} else {
		panic(W.InvalidArchError)
	}
}

func (emu *Emulator) GetInstructionPointer() AS.VA {
	logrus.Debug("emulator: get insn pointer")
	var r uint64
	var e error
	if emu.ws.Arch == W.ARCH_X86 {
		if emu.ws.Mode == W.MODE_32 {
			r, e = emu.RegRead(uc.X86_REG_EIP)
		} else if emu.ws.Mode == W.MODE_64 {
			r, e = emu.RegRead(uc.X86_REG_RIP)
		} else {
			panic(W.InvalidModeError)
		}
	} else {
		panic(W.InvalidArchError)
	}
	if e != nil {
		panic(e)
	}
	return AS.VA(r)
}

// utility method for handling the uint64 casting
func (emu *Emulator) start(begin AS.VA, until AS.VA) error {
	logrus.Debug("emulator: start")
	return emu.u.Start(uint64(begin), uint64(until))
}

func (emu *Emulator) removeHook(h uc.Hook) error {
	logrus.Debugf("emulator: remove hook: %v", h)
	e := emu.u.HookDel(h)
	check(e)
	return e
}

func (emu *Emulator) HookMemRead(f MemReadHandler) (CloseableHook, error) {
	if emu.hooks.memRead == nil {
		m, e := newHookMultiplexer()
		if e != nil {
			return nil, e
		}
		emu.hooks.memRead = m
		e = emu.hooks.memRead.Install(emu, uc.HOOK_MEM_READ)
		if e != nil {
			return nil, e
		}
	}
	return emu.hooks.memRead.AddHook(f)
}

func (emu *Emulator) HookMemWrite(f MemWriteHandler) (CloseableHook, error) {
	if emu.hooks.memWrite == nil {
		m, e := newHookMultiplexer()
		if e != nil {
			return nil, e
		}
		emu.hooks.memWrite = m
		e = emu.hooks.memWrite.Install(emu, uc.HOOK_MEM_WRITE)
		if e != nil {
			return nil, e
		}
	}
	return emu.hooks.memWrite.AddHook(f)
}

func (emu *Emulator) HookMemUnmapped(f MemUnmappedHandler) (CloseableHook, error) {
	if emu.hooks.memUnmapped == nil {
		m, e := newHookMultiplexer()
		if e != nil {
			return nil, e
		}
		emu.hooks.memUnmapped = m
		e = emu.hooks.memUnmapped.Install(emu, uc.HOOK_MEM_UNMAPPED)
		if e != nil {
			return nil, e
		}

	}
	return emu.hooks.memUnmapped.AddHook(f)
}

func (emu *Emulator) HookCode(f CodeHandler) (CloseableHook, error) {
	if emu.hooks.code == nil {
		m, e := newHookMultiplexer()
		if e != nil {
			return nil, e
		}
		emu.hooks.code = m
		e = emu.hooks.code.Install(emu, uc.HOOK_CODE)
		if e != nil {
			return nil, e
		}

	}
	return emu.hooks.code.AddHook(f)
}

func (emu *Emulator) traceMemUnmapped(err *error) (CloseableHook, error) {
	return emu.HookMemUnmapped(func(access int, addr AS.VA, size int, value int64) bool {
		logrus.Warnf("Emulator: error: memory unmapped: %s len: %x", addr, size)
		*err = AS.ErrUnmappedMemory
		return true
	})
}

func (emu *Emulator) traceMemRead() (CloseableHook, error) {
	return emu.HookMemRead(func(access int, addr AS.VA, size int, value int64) {
		logrus.Debugf("Emulator: read: %s length: 0x%x value: 0x%x", addr, size, value)
	})
}

func (emu *Emulator) traceMemWrite() (CloseableHook, error) {
	return emu.HookMemWrite(func(access int, addr AS.VA, size int, value int64) {
		logrus.Debugf("Emulator: write: %s length: 0x%x value: 0x%x", addr, size, value)
	})
}

func (emu *Emulator) traceInsn() (CloseableHook, error) {
	return emu.HookCode(func(addr AS.VA, size uint32) {
		logrus.Debugf("Emulator: insn: %s length: 0x%x", addr, size)
	})
}

func DumpMemoryRegions(as AS.AddressSpace) error {
	fmt.Printf("=== memory map ===\n")
	mmaps, e := as.GetMaps()
	check(e)
	for _, region := range mmaps {
		fmt.Printf("  name: %s\n", region.Name)
		fmt.Printf("    address: %s\n", region.Address)
		fmt.Printf("    length: %x\n", region.Length)
	}
	return nil
}

func (emu *Emulator) RunTo(address AS.VA) error {
	logrus.Debugf("emulator: runto: to: %s", address)
	ip := emu.GetInstructionPointer()
	logrus.Debugf("emulator: runto: from: %s to: %s", ip, address)

	var memErr error = nil
	// TODO: remove these traces
	memHook, e := emu.traceMemUnmapped(&memErr)
	check(e)
	defer memHook.Close()

	insnHook, e := emu.traceInsn()
	check(e)
	defer insnHook.Close()

	logrus.Debugf("Emulator RunTo: from: %s to: %s, start", ip, address)
	e = emu.start(ip, address)
	logrus.Debugf("Emulator RunTo: from: %s to: %s, end", ip, address)
	if memErr != nil {
		return memErr
	}
	return e
}

var EmulatorEscapedError = errors.New("Emulator failed to stop as requested.")

func (emu *Emulator) StepInto() error {
	logrus.Debugf("emulator: step into")
	var memErr error = nil
	var codeErr error = nil

	memHook, e := emu.traceMemUnmapped(&memErr)
	check(e)
	defer memHook.Close()

	// always stop after one instruction
	hitCount := 0
	h, e := emu.HookCode(func(addr AS.VA, size uint32) {
		if hitCount == 0 {
			// pass
		} else if hitCount == 1 {
			emu.u.Stop()
		} else {
			codeErr = EmulatorEscapedError
		}
		hitCount++
	})
	check(e)
	defer h.Close()

	insn, e := emu.GetCurrentInstruction()
	ip := emu.GetInstructionPointer()
	end := AS.VA(uint64(ip) + uint64(insn.Size))
	e = emu.start(ip, end)
	if e != nil {
		logrus.Warnf("Single step failed: %s", e.Error())
		switch e := e.(type) {
		case uc.UcError:
			// TODO: nested switch here
			// TODO: split out into utility function??
			if e == uc.ERR_FETCH_UNMAPPED {
				return AS.ErrInvalidMemoryExec
			} else if e == uc.ERR_READ_UNMAPPED {
				return AS.ErrInvalidMemoryRead
			} else if e == uc.ERR_WRITE_UNMAPPED {
				return AS.ErrInvalidMemoryWrite
			}
			break
		default:
			break
		}
		return e
	}
	if memErr != nil {
		return memErr
	}
	if codeErr != nil {
		return codeErr
	}

	return nil
}

func (emu *Emulator) GetCurrentInstruction() (gapstone.Instruction, error) {
	ip := emu.GetInstructionPointer()
	return dis.ReadInstruction(emu.disassembler, emu, ip)
}

func (emu *Emulator) StepOver() error {
	logrus.Debugf("emulator: step over")
	insn, e := emu.GetCurrentInstruction()
	check(e)
	if e != nil {
		return e
	}

	if dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
		return emu.RunTo(AS.VA(uint64(emu.GetInstructionPointer()) + uint64(insn.Size)))
	} else {
		return emu.StepInto()
	}
}

func min(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// return: data at va formatted appropriately, number of bytes for va formatted, error
func (emu *Emulator) FormatAddress(va AS.VA) (string, uint64, error) {
	// assume everything is code right now

	insn, e := dis.ReadInstruction(emu.disassembler, emu, va)
	check(e)

	// fetch either instruction length, or max configured bytes, amount of data
	numBytes := uint64(emu.ws.DisplayOptions.NumOpcodeBytes)
	d, e := emu.MemRead(va, min(uint64(insn.Size), numBytes))
	check(e)

	// format each of those as hex
	var bytesPrefix []string
	for _, b := range d {
		bytesPrefix = append(bytesPrefix, fmt.Sprintf("%02X", b))
	}
	// and fill in padding space
	for i := uint64(len(d)); i < numBytes; i++ {
		bytesPrefix = append(bytesPrefix, "  ")
	}
	prefix := strings.Join(bytesPrefix, " ")

	ret := fmt.Sprintf("0x%x: %s %s\t%s", insn.Address, prefix, insn.Mnemonic, insn.OpStr)
	return ret, uint64(insn.Size), nil
}
