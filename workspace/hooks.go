package workspace

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type CloseableHook interface {
	Close() error
}

type UnicornCloseableHook struct {
	emu *Emulator
	h   uc.Hook
}

func (hook *UnicornCloseableHook) Close() error {
	return hook.emu.removeHook(hook.h)
}

type Cookie uint64
type MemReadHandler func(access int, addr VA, size int, value int64)
type MemWriteHandler func(access int, addr VA, size int, value int64)

/************ MEM READ ****************************/

type MemReadHookMultiplexer struct {
	h       *CloseableHook
	counter uint64
	entries map[Cookie]MemReadHandler
}

func NewMemReadHookMultiplexer() (*MemReadHookMultiplexer, error) {
	return &MemReadHookMultiplexer{
		counter: 0,
		entries: make(map[Cookie]MemReadHandler),
	}, nil
}

func (m *MemReadHookMultiplexer) AddHook(f MemReadHandler) (Cookie, error) {
	cookie := Cookie(m.counter)
	m.counter++
	m.entries[cookie] = f
	return cookie, nil
}

func (m *MemReadHookMultiplexer) RemoveHook(c Cookie) error {
	// TODO: check if c exists
	delete(m.entries, c)
	return nil
}

func (m *MemReadHookMultiplexer) Install(emu *Emulator) error {
	// TODO: ensure multiplexer not already installed
	// TODO: ensure emu not already hooked

	h, e := emu.u.HookAdd(
		uc.HOOK_MEM_READ,
		func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
			for _, f := range m.entries {
				f(access, VA(addr), size, value)
			}
		})

	check(e)
	if e != nil {
		return e
	}

	m.h = &CloseableHook{emu: emu, h: h}
	return nil
}

func (m *MemReadHookMultiplexer) Close() error {
	return m.h.Close()
}

type MemReadCloseableHook struct {
	m *MemReadHookMultiplexer
	c Cookie
}

func (h *MemReadCloseableHook) Close() error {
	return h.m.RemoveHook(h.c)
}

func (emu *Emulator) HookMemRead(f MemReadHandler) (*CloseableHook, error) {
	h, e := emu.u.HookAdd(
		uc.HOOK_MEM_READ,
		func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
			f(access, VA(addr), size, value)
		})

	check(e)
	if e != nil {
		return nil, e
	}

	return &MemReadCloseableHook{emu: emu, h: h}, nil
}

/************ MEM WRITE ****************************/

func (emu *Emulator) HookMemWrite(f func(access int, addr W.VA, size int, value int64)) (*CloseableHook, error) {

}
