package dora

import (
	"github.com/bnagy/gapstone"
	"github.com/fatih/color"
	w "github.com/williballenthin/Lancelot/workspace"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// dora the explora
type Dora struct {
	ws *w.Workspace
	ac ArtifactCollection
}

func New(ws *w.Workspace) (*Dora, error) {
	// TODO: get this from a real place
	ac, e := NewLoggingArtifactCollection()
	check(e)

	return &Dora{
		ws: ws,
		ac: ac,
	}, nil
}

func isBBEnd(insn gapstone.Instruction) bool {
	return w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) ||
		w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) ||
		w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
		w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET)
}

// things yet to discover:
//   TODO: arguments passed in registers
//   TODO: arguments passed on stack
//   OK: final stack delta
//   TODO: all basic blocks
//   TODO: calling convention
// TODO: ensure stack is set up with return pointer and some junk symbolic args
func (dora *Dora) ExploreFunction(va w.VA) error {
	emu, e := dora.ws.GetEmulator()
	check(e)
	defer emu.Close()

	bbStart := va
	emu.SetInstructionPointer(va)
	check(e)

	beforeSp := emu.GetStackPointer()

	rh, e := emu.HookMemRead(func(access int, addr w.VA, size int, value int64) {
		dora.ac.AddMemoryReadXref(MemoryReadCrossReference{emu.GetInstructionPointer(), addr})
	})
	check(e)
	defer rh.Close()

	wh, e := emu.HookMemWrite(func(access int, addr w.VA, size int, value int64) {
		dora.ac.AddMemoryWriteXref(MemoryWriteCrossReference{emu.GetInstructionPointer(), addr})
	})
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

		if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
			// emulate the call instruction to determine its target

			// TODO: have to wire up import detection

			//check(emu.UnhookSnapshot(snap))
			tsnap, e := emu.Snapshot()
			check(e)

			e = emu.StepInto()
			check(e)

			nextPc := emu.GetInstructionPointer()
			e = emu.RestoreSnapshot(tsnap)
			check(e)

			e = emu.UnhookSnapshot(tsnap)
			check(e)
			//emu.HookSnapshot(snap)

			dora.ac.AddCallXref(CallCrossReference{emu.GetInstructionPointer(), nextPc})
		}

		if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) {
			log.Printf("returning, done.")
			afterSp := emu.GetStackPointer()
			stackDelta := uint64(afterSp) - uint64(beforeSp)
			log.Printf("stack delta: 0x%x", stackDelta)
			break
		}

		if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET) {
			log.Printf("returning, done.")
			afterSp := emu.GetStackPointer()
			stackDelta := uint64(afterSp) - uint64(beforeSp)
			log.Printf("stack delta: 0x%x", stackDelta)
			break
		}

		if isBBEnd(insn) {
			e := dora.ac.AddBasicBlock(BasicBlock{Start: bbStart, End: emu.GetInstructionPointer()})
			check(e)
		}

		beforePc := emu.GetInstructionPointer()
		e = emu.StepOver()
		if e != nil {
			log.Printf("error: %s", e.Error())
			break
		}
		afterPc := emu.GetInstructionPointer()

		// TODO: need to detect calling convention, and in the case of stdcall,
		//   cleanup the stack

		if isBBEnd(insn) {
			bbStart = emu.GetInstructionPointer()
			e := dora.ac.AddJumpXref(JumpCrossReference{beforePc, afterPc})
			check(e)
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
