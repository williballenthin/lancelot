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

func GetNextInstructionPointer(emu *w.Emulator, sman *w.SnapshotManager) (w.VA, error) {
	var va w.VA
	e := sman.WithTempExcursion(func() error {
		e := emu.StepInto()
		if e != nil {
			return e
		}
		va = emu.GetInstructionPointer()
		return nil
	})
	return va, e
}

type todoPath struct {
	state w.SnapshotManagerCookie
	va    w.VA
}

func IsConditionalJump(insn gapstone.Instruction) bool {
	if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic != "jmp" {
		return true
	}
	if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic == "jmp" {
		if insn.Mnemonic == "jmp" && insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
			// jmp 0x1000
			return false
		} else {
			// jmp eax
			return true
		}
	}
	return false
}

func GetJumpTargets(emu *w.Emulator, insn gapstone.Instruction) ([]w.VA, error) {
	var ret []w.VA

	if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) && insn.Mnemonic == "jmp" {
		if insn.X86.Operands[0].Type == gapstone.X86_OP_IMM {
			// not a conditional jump???
			return ret, w.InvalidArgumentError
		}
		// jmp eax
		// don't know how to handle this case right now
		return ret, nil
	}

	// assume a two case situation
	falsePc := w.VA(uint64(emu.GetInstructionPointer()) + uint64(insn.Size))
	truePc := w.VA(insn.X86.Operands[0].Imm) // or .Mem???

	if truePc == 0 {
		// TODO
		panic("zero jump")
	}

	ret = append(ret, truePc, falsePc)
	return ret, nil
}

// things yet to discover:
//   OK: final stack delta
//   TODO: arguments passed in registers
//     insn.cs_detail.regs_read/regs_write
//   TODO: arguments passed on stack
//   OK: all basic blocks
//   TODO: calling convention
//   TODO: no return functions
// TODO: ensure stack is set up with return pointer and some junk symbolic args
// TODO: track max hits
// this is going to be a pretty wild function :-(
func (dora *Dora) ExploreFunction(va w.VA) error {
	emu, e := dora.ws.GetEmulator()
	check(e)
	defer emu.Close()

	sman, e := w.NewSnapshotManager(emu)
	check(e)
	defer sman.Close()

	bbStart := va
	emu.SetInstructionPointer(va)
	check(e)

	beforeSp := emu.GetStackPointer()

	// TODO: how to disable these while on an excursion?
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

	hitVas := make(map[w.VA]bool)

	var todoPaths = []todoPath{}
	here, e := sman.GetCurrentCookie()
	check(e)
	todoPaths = append(todoPaths, todoPath{state: here, va: va})

	for len(todoPaths) > 0 {
		path := todoPaths[len(todoPaths)-1]
		todoPaths = todoPaths[1:]
		log.Printf("exploring path %s: va=0x%x", path.state, path.va)
		check(sman.RevertUntil(path.state))
		emu.SetInstructionPointer(path.va)

		for {
			// TODO: dora.checkVisitedVas()
			if _, ok := hitVas[emu.GetInstructionPointer()]; ok {
				break
			}

			// TODO: dora.tracePc()
			s, _, e := emu.FormatAddress(emu.GetInstructionPointer())
			check(e)
			color.Set(color.FgHiBlack)
			log.Printf("ip:" + s)
			color.Unset()

			insn, e := emu.GetCurrentInstruction()
			check(e)

			if isBBEnd(insn) {
				e := dora.ac.AddBasicBlock(BasicBlock{Start: bbStart, End: emu.GetInstructionPointer()})
				check(e)
			}

			beforePc := emu.GetInstructionPointer()
			// TODO: dora.handleRet()
			// TODO: dora.handleConditionalJump()
			// TODO: dora.handleJump()
			// TODO: dora.handleCall()
			// TODO: dora.handleStep()
			if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
				w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET) {
				log.Printf("returning, done.")
				afterSp := emu.GetStackPointer()
				stackDelta := uint64(afterSp) - uint64(beforeSp)
				log.Printf("stack delta: 0x%x", stackDelta)
				break
			} else if IsConditionalJump(insn) {
				targets, e := GetJumpTargets(emu, insn)
				check(e)
				if len(targets) < 2 {
					// TODO: by definition, a conditional jump should have at least two cases...
					panic("len(targets) < 2")
				}

				here, e := sman.Push()
				check(e)

				nextPc := targets[0]
				for _, target := range targets[1:] {
					log.Printf("other target: 0x%x", target)
					todoPaths = append(todoPaths, todoPath{state: here, va: target})
				}
				emu.SetInstructionPointer(nextPc)

			} else if w.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
				// TODO: try to resolve imports before blindly emulating
				callPc, e := GetNextInstructionPointer(emu, sman)
				if e == nil {
					log.Printf("  call target: 0x%x", callPc)
				}
				dora.ac.AddCallXref(CallCrossReference{emu.GetInstructionPointer(), callPc})

				nextPc := w.VA(uint64(emu.GetInstructionPointer()) + uint64(insn.Size))
				emu.SetInstructionPointer(nextPc)

				// TODO: need to detect calling convention, and in the case of stdcall,
				//   cleanup the stack

			} else {
				e = emu.StepOver()
				if e != nil {
					log.Printf("error: %s", e.Error())
					break
				}
			}

			// TODO: fetch stack read/write set for arg/variable detection
			// TODO: fetch reg read/write set for arg detection

			// TODO: dora.updateVisitedVas()
			hitVas[beforePc] = true

			afterPc := emu.GetInstructionPointer()
			if isBBEnd(insn) {
				bbStart = emu.GetInstructionPointer()
				e := dora.ac.AddJumpXref(JumpCrossReference{beforePc, afterPc})
				check(e)
			}
		}
	}

	return nil
}
