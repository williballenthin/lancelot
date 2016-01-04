package workspace

import (
	"errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	AS "github.com/williballenthin/Lancelot/address_space"
	"log"
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
type MemReadHandler func(access int, addr AS.VA, size int, value int64)
type MemWriteHandler func(access int, addr AS.VA, size int, value int64)
type MemUnmappedHandler func(access int, addr AS.VA, size int, value int64) bool
type CodeHandler func(addr AS.VA, size uint32)

/************ internal ****************************/
/* need to be careful with typing, so do not expose Interface{} */

// intended possible concrete types:
//   MemReadHandler
//   MemWriteHandler
//   MemUnmappedHandler
//   CodeHandler
type Handler interface{}

type hookMultiplexer struct {
	h       CloseableHook
	counter uint64
	entries map[Cookie]Handler
}

func newHookMultiplexer() (*hookMultiplexer, error) {
	return &hookMultiplexer{
		counter: 0,
		entries: make(map[Cookie]Handler),
	}, nil
}

type multiplexerCloseableHook struct {
	m *hookMultiplexer
	c Cookie
}

func (h *multiplexerCloseableHook) Close() error {
	return h.m.removeHook(h.c)
}

func (m *hookMultiplexer) AddHook(f Handler) (CloseableHook, error) {
	cookie := Cookie(m.counter)
	m.counter++
	m.entries[cookie] = f
	return &multiplexerCloseableHook{m: m, c: cookie}, nil
}

func (m *hookMultiplexer) removeHook(c Cookie) error {
	// TODO: check if c exists
	delete(m.entries, c)
	return nil
}

var ErrInvalidArgument = errors.New("Invalid argument")
var ErrAlreadyHooked = errors.New("Multiplexer already hooked")

func (m *hookMultiplexer) Install(emu *Emulator, hookType int) error {
	// TODO: ensure multiplexer not already installed
	if m.h != nil {
		return ErrAlreadyHooked
	}

	switch hookType {
	case uc.HOOK_MEM_READ:
		h, e := emu.u.HookAdd(
			uc.HOOK_MEM_READ,
			func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
				for _, f := range m.entries {
					if f, ok := f.(MemReadHandler); ok {
						f(access, AS.VA(addr), size, value)
					} else {
						log.Printf("error: failed to convert handler to mem read handler")
					}
				}
			})

		check(e)
		if e != nil {
			return e
		}

		m.h = &UnicornCloseableHook{emu: emu, h: h}
		return nil
	case uc.HOOK_MEM_WRITE:
		h, e := emu.u.HookAdd(
			uc.HOOK_MEM_WRITE,
			func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
				for _, f := range m.entries {
					if f, ok := f.(MemWriteHandler); ok {
						f(access, AS.VA(addr), size, value)
					} else {
						log.Printf("error: failed to convert handler to mem write handler")
					}
				}
			})

		check(e)
		if e != nil {
			return e
		}

		m.h = &UnicornCloseableHook{emu: emu, h: h}
		return nil
	case uc.HOOK_MEM_UNMAPPED:
		h, e := emu.u.HookAdd(
			uc.HOOK_MEM_UNMAPPED,
			func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
				for _, f := range m.entries {
					if f, ok := f.(MemUnmappedHandler); ok {
						if !f(access, AS.VA(addr), size, value) {
							return false
						}
					} else {
						log.Printf("error: failed to convert handler to mem unmapped handler")
					}
				}
				return true
			})

		check(e)
		if e != nil {
			return e
		}

		m.h = &UnicornCloseableHook{emu: emu, h: h}
		return nil
	case uc.HOOK_CODE:
		h, e := emu.u.HookAdd(
			uc.HOOK_CODE,
			func(mu uc.Unicorn, addr uint64, size uint32) {
				for _, f := range m.entries {
					if f, ok := f.(CodeHandler); ok {
						f(AS.VA(addr), uint32(size))
					} else {
						log.Printf("error: failed to convert handler to mem unmapped handler")
					}
				}
			})

		check(e)
		if e != nil {
			return e
		}

		m.h = &UnicornCloseableHook{emu: emu, h: h}
		return nil

	default:
		return ErrInvalidArgument
	}
}

func (m *hookMultiplexer) Close() error {
	return m.h.Close()
}
