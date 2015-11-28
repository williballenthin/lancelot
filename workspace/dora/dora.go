package dora

import (
	"github.com/bnagy/gapstone"
	"github.com/fatih/color"
	W "github.com/williballenthin/Lancelot/workspace"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// dora the explora
type Dora struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*Dora, error) {
	return &Dora{
		ws: ws,
	}, nil
}

func (dora *Dora) addBasicBlock(start W.VA, end W.VA) error {
	log.Printf("discovered basic block: 0x%x 0x%x", start, end)

	return nil
}

func (dora *Dora) endBasicBlock() error {
	log.Printf("end basic block")

	return nil
}

func isBBEnd(insn gapstone.Instruction) bool {
	return W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) ||
		W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) ||
		W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
		W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET)
}

func (dora *Dora) memReadHookFunc(access int, addr W.VA, size int, value int64) {
	log.Printf("dora: read: @0x%x [0x%x] = 0x%x", addr, size, value)
}

func (dora *Dora) memWriteHookFunc(access int, addr W.VA, size int, value int64) {
	log.Printf("dora: write: @0x%x [0x%x] = 0x%x", addr, size, value)
}

func (dora *Dora) ExploreFunction(va W.VA) error {
	emu, e := dora.ws.GetEmulator()
	check(e)
	defer emu.Close()

	bbStart := va
	emu.SetInstructionPointer(va)
	check(e)

	rh, e := emu.HookMemRead(dora.memReadHookFunc)
	check(e)
	defer rh.Close()

	wh, e := emu.HookMemWrite(dora.memWriteHookFunc)
	check(e)
	defer wh.Close()

	for {
		s, _, e := emu.FormatAddress(emu.GetInstructionPointer())
		check(e)
		color.Set(color.FgHiBlack)
		log.Printf("ip:" + s)
		color.Unset()

		insn, e := emu.GetCurrentInstruction()
		check(e)

		if W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			log.Printf("this is a call")
		}

		if W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
			log.Printf("returning, done.")
			break
		}

		if W.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET) {
			log.Printf("returning, done.")
			break
		}

		if isBBEnd(insn) {
			e := dora.addBasicBlock(bbStart, emu.GetInstructionPointer())
			check(e)
		}

		e = emu.StepOver()
		if e != nil {
			log.Printf("error: %s", e.Error())
			break
		}

		if isBBEnd(insn) {
			bbStart = emu.GetInstructionPointer()
			log.Printf("bb start")
		}
	}

	/*
		snap, e := dora.emu.Snapshot()
		check(e)

		defer func() {
			e := dora.emu.RestoreSnapshot(snap)
			check(e)

			e = dora.emu.UnhookSnapshot(snap)
			check(e)
		}()
	*/

	return nil
}
