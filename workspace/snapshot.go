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

func (emu *Emulator) SnapshotRegisters() (*RegisterSnapshot, error) {
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

func (emu *Emulator) RestoreRegisterSnapshot(regs *RegisterSnapshot) error {
	for i := uc.X86_REG_INVALID + 1; i < uc.X86_REG_ENDING; i++ {
		e := emu.u.RegWrite(i, regs.regs[i])
		if e != nil {
			return e
		}
	}
	return nil
}

func (emu *Emulator) SnapshotMemory() (*MemorySnapshot, error) {
	return CreateMemorySnapshot(emu)
}

// until i figure out how this is best used,
// the currentAddressSpace of `snapshot` *must* be be this emu.
func (emu *Emulator) RestoreMemorySnapshot(as *MemorySnapshot) error {
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

var SnapshotHookAlreadyActive = errors.New("Snapshot hook already active")

func (emu *Emulator) HookSnapshot(snap *Snapshot) error {
	if snap.hook != nil {
		return SnapshotHookAlreadyActive
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

var SnapshotHookNotActive = errors.New("Snapshot hook not active")

func (emu *Emulator) UnhookSnapshot(snap *Snapshot) error {
	if snap.hook == nil {
		return SnapshotHookNotActive
	}

	e := snap.hook.Close()
	snap.hook = nil
	return e
}

func (emu *Emulator) Snapshot() (*Snapshot, error) {
	regs, e := emu.SnapshotRegisters()
	if e != nil {
		return nil, e
	}

	mem, e := emu.SnapshotMemory()
	if e != nil {
		return nil, e
	}

	snap := &Snapshot{
		hook:      nil,
		memory:    mem,
		registers: regs,
	}

	e = emu.HookSnapshot(snap)
	if e != nil {
		return nil, e
	}

	return snap, nil
}

func (emu *Emulator) RestoreSnapshot(snap *Snapshot) error {
	e := emu.RestoreRegisterSnapshot(snap.registers)
	check(e)
	if e != nil {
		// we're in a bad state here
		return e
	}
	e = emu.RestoreMemorySnapshot(snap.memory)
	if e != nil {
		// we're in a bad state here
		return e
	}
	return nil
}

func (snap Snapshot) String() string {
	return fmt.Sprintf("snapshot: eip=0x%x", snap.registers.regs[uc.X86_REG_EIP])
}
