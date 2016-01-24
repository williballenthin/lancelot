package emulator

import (
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	AS "github.com/williballenthin/Lancelot/address_space"
)

// naturally, x86 specific. mode-agnostic.
type RegisterSnapshot struct {
	regs [uc.X86_REG_ENDING - uc.X86_REG_INVALID]uint64
}

func SnapshotRegisters(emu *Emulator) (*RegisterSnapshot, error) {
	logrus.Debugf("snapshot: create registers")
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
	logrus.Debugf("snapshot: restore registers")
	for i := uc.X86_REG_INVALID + 1; i < uc.X86_REG_ENDING; i++ {
		e := emu.u.RegWrite(i, regs.regs[i])
		if e != nil {
			return e
		}
	}
	return nil
}

func SnapshotMemory(emu *Emulator) (*AS.MemorySnapshot, error) {
	logrus.Debugf("snapshot: create memory")
	return AS.CreateMemorySnapshot(emu)
}

// until i figure out how this is best used,
// the currentAddressSpace of `snapshot` *must* be be this emu.
func RestoreMemorySnapshot(emu *Emulator, as *AS.MemorySnapshot) error {
	logrus.Debugf("snapshot: restore memory")
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
	memory    *AS.MemorySnapshot
	registers *RegisterSnapshot
}

var ErrSnapshotHookAlreadyActive = errors.New("Snapshot hook already active")

func HookSnapshot(emu *Emulator, snap *Snapshot) error {
	logrus.Debugf("snapshot: hook")
	if snap.hook != nil {
		return ErrSnapshotHookAlreadyActive
	}

	h, e := emu.HookMemWrite(func(access int, addr AS.VA, size int, value int64) {
		for i := uint64(addr); i < uint64(addr)+uint64(size); i += AS.PAGE_SIZE {
			snap.memory.MarkDirty(AS.VA(i))
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
	logrus.Debugf("snapshot: unhook")
	if snap.hook == nil {
		return ErrSnapshotHookNotActive
	}

	e := snap.hook.Close()
	snap.hook = nil
	return e
}

func CreateSnapshot(emu *Emulator) (*Snapshot, error) {
	logrus.Debugf("snapshot: create")
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
	logrus.Debugf("snapshot: restore")
	e := RestoreRegisterSnapshot(emu, snap.registers)
	check(e)
	if e != nil {
		// we're in a bad state here
		return e
	}
	e = RestoreMemorySnapshot(emu, snap.memory)
	check(e)
	if e != nil {
		// we're in a bad state here
		return e
	}
	return nil
}

func (snap Snapshot) String() string {
	return fmt.Sprintf("snapshot: eip=0x%x", snap.registers.regs[uc.X86_REG_EIP])
}

/************* SnapshotManager *******************/

type SnapshotManagerCookie uint64

func (c SnapshotManagerCookie) String() string {
	return fmt.Sprintf("0x%x", uint64(c))

}

type snapshotManagerState struct {
	snap *Snapshot
	c    SnapshotManagerCookie
}

type SnapshotManager struct {
	emu     *Emulator
	states  []*snapshotManagerState
	counter uint64
}

func NewSnapshotManager(emu *Emulator) (*SnapshotManager, error) {
	t := &SnapshotManager{
		emu:     emu,
		states:  make([]*snapshotManagerState, 0),
		counter: 1,
	}

	// prime initial state
	_, e := t.Push()
	check(e)

	return t, nil
}

func (t *SnapshotManager) Close() error {
	logrus.Debugf("snapshot manager: close")
	for len(t.states) > 1 {
		_, e := t.Pop()
		check(e)
	}
	check(UnhookSnapshot(t.emu, t.states[0].snap))
	t.states = nil
	return nil
}

func (t *SnapshotManager) Push() (SnapshotManagerCookie, error) {
	logrus.Debugf("snapshot manager: push")
	c := SnapshotManagerCookie(t.counter)
	t.counter++

	if len(t.states) > 0 {
		currentState := t.states[len(t.states)-1]
		// don't check this, because we might unhook
		//  the initial state multiple times
		UnhookSnapshot(t.emu, currentState.snap)
	}

	snap, e := CreateSnapshot(t.emu)
	check(e)

	check(HookSnapshot(t.emu, snap))

	state := &snapshotManagerState{
		snap: snap,
		c:    c,
	}

	t.states = append(t.states, state)

	return c, nil
}

var ErrSnapshotNotActive = errors.New("Snapshot not active")

func (t *SnapshotManager) RevertToHead() error {
	logrus.Debugf("snapshot manager: revert to head")
	if len(t.states) == 0 {
		panic(ErrSnapshotNotActive)
	}

	state := t.states[len(t.states)-1]
	return RestoreSnapshot(t.emu, state.snap)
}

func (t *SnapshotManager) Pop() (SnapshotManagerCookie, error) {
	logrus.Debugf("snapshot manager: pop")
	if len(t.states) == 0 {
		panic(ErrSnapshotNotActive)
	}

	state := t.states[len(t.states)-1]

	if len(t.states) > 1 {
		check(UnhookSnapshot(t.emu, state.snap))

		t.states = t.states[:len(t.states)-1]

		prevState := t.states[len(t.states)-1]
		check(HookSnapshot(t.emu, prevState.snap))
	}
	return state.c, nil
}

func (t *SnapshotManager) GetCurrentCookie() (SnapshotManagerCookie, error) {
	if len(t.states) == 0 {
		panic(ErrSnapshotNotActive)
	}

	state := t.states[len(t.states)-1]
	return state.c, nil
}

var ErrSnapshotNotFound = errors.New("Snapshot cookie not found")

func (t *SnapshotManager) RevertUntil(c SnapshotManagerCookie) error {
	logrus.Debugf("snapshot manager: revert until")
	var lastCookie SnapshotManagerCookie
	for {
		check(t.RevertToHead())

		cookie, e := t.GetCurrentCookie()
		check(e)

		if cookie == c {
			break
		}
		// ensure we don't get stuck on the initial state
		if cookie == lastCookie {
			return ErrSnapshotNotFound
		}
		lastCookie = cookie

		_, e = t.Pop()
		check(e)
	}
	return nil
}

func (t *SnapshotManager) WithTempExcursion(f func() error) error {
	logrus.Debugf("snapshot manager: with temp exursion")
	beforeCookie, e := t.Push()
	check(e)

	var ret error
	e = f()
	if e != nil {
		ret = e
	}

	check(t.RevertUntil(beforeCookie))
	_, e = t.Pop()
	check(e)

	return ret
}
