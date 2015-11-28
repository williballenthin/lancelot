package workspace

import (
	"errors"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// naturally, x86 specific. mode-agnostic.
type RegisterSnapshot struct {
	regs [uc.X86_REG_ENDING - uc.X86_REG_INVALID]uint64
}

func SnapshotRegisters(emu *Emulator) (*RegisterSnapshot, error) {
	var regs RegisterSnapshot
	for i := uc.X86_REG_INVALID + 1; i < uc.X86_REG_ENDING; i++ {
		r, e := emu.u.RegRead(i)
		if e != nil {
			return nil, e
		}
		regs.regs[i] = r
	}
	return &regs, nil
}

func RestoreRegisterSnapshot(emu *Emulator, regs *RegisterSnapshot) error {
	for i := uc.X86_REG_INVALID + 1; i < uc.X86_REG_ENDING; i++ {
		e := emu.u.RegWrite(i, regs.regs[i])
		if e != nil {
			return e
		}
	}
	return nil
}

func SnapshotMemory(emu *Emulator) (*MemorySnapshot, error) {
	return CreateMemorySnapshot(emu)
}

// until i figure out how this is best used,
// the currentAddressSpace of `snapshot` *must* be be this emu.
func RestoreMemorySnapshot(emu *Emulator, as *MemorySnapshot) error {
	e := as.RevertAddressSpace(emu)
	if e != nil {
		return e
	}

	e = as.Revert()
	check(e)

	return nil
}

// x86 specific. mode-agnostic.
type Snapshot struct {
	hook      CloseableHook
	emu       *Emulator
	memory    *MemorySnapshot
	registers *RegisterSnapshot
}

var ErrSnapshotHookAlreadyActive = errors.New("Snapshot hook already active")

func HookSnapshot(emu *Emulator, snap *Snapshot) error {
	if snap.hook != nil {
		return ErrSnapshotHookAlreadyActive
	}

	h, e := emu.HookMemWrite(func(access int, addr VA, size int, value int64) {
		for i := uint64(addr); i < uint64(addr)+uint64(size); i += PAGE_SIZE {
			snap.memory.MarkDirty(VA(i))
		}
	})
	check(e)
	if e != nil {
		return e
	}

	snap.hook = h
	return nil
}

var ErrSnapshotHookNotActive = errors.New("Snapshot hook not active")

func UnhookSnapshot(emu *Emulator, snap *Snapshot) error {
	if snap.hook == nil {
		return ErrSnapshotHookNotActive
	}

	e := snap.hook.Close()
	snap.hook = nil
	return e
}

func CreateSnapshot(emu *Emulator) (*Snapshot, error) {
	regs, e := SnapshotRegisters(emu)
	if e != nil {
		return nil, e
	}

	mem, e := SnapshotMemory(emu)
	if e != nil {
		return nil, e
	}

	snap := &Snapshot{
		hook:      nil,
		memory:    mem,
		registers: regs,
	}

	return snap, nil
}

func RestoreSnapshot(emu *Emulator, snap *Snapshot) error {
	e := RestoreRegisterSnapshot(emu, snap.registers)
	check(e)
	if e != nil {
		// we're in a bad state here
		return e
	}
	e = RestoreMemorySnapshot(emu, snap.memory)
	if e != nil {
		// we're in a bad state here
		return e
	}
	return nil
}

func (snap Snapshot) String() string {
	return fmt.Sprintf("snapshot: eip=0x%x", snap.registers.regs[uc.X86_REG_EIP])
}
