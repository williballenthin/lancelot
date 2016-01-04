package dora

import (
	"github.com/bnagy/gapstone"
	"github.com/fatih/color"
	AS "github.com/williballenthin/Lancelot/address_space"
	"github.com/williballenthin/Lancelot/artifacts"
	dis "github.com/williballenthin/Lancelot/disassembly"
	E "github.com/williballenthin/Lancelot/emulator"
	W "github.com/williballenthin/Lancelot/workspace"
	"log"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// InstructionTraceHandler is a function that can process instructions
//  parsed by this package.
// Use insn.Address for the current address.
type InstructionTraceHandler func(insn gapstone.Instruction) error

// JumpTraceHandler is a function that can process control flow edges
//  parsed by this package.
// Use insn.Address for the source address.
// Use bb for the address of the source basic block.
type JumpTraceHandler func(insn gapstone.Instruction, xref *artifacts.JumpCrossReference) error

func isBBEnd(insn gapstone.Instruction) bool {
	return dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_JUMP) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
		dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET)
}

func GetNextInstructionPointer(emu *E.Emulator, sman *E.SnapshotManager) (AS.VA, error) {
	var va AS.VA
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

// dora the explora
type Dora struct {
	ws *W.Workspace
	ac artifacts.ArtifactCollection
}

func New(ws *W.Workspace) (*Dora, error) {
	// TODO: get this from a real place
	ac, e := artifacts.NewLoggingArtifactCollection()
	check(e)

	return &Dora{
		ws: ws,
		ac: ac,
	}, nil
}

type todoPath struct {
	state E.SnapshotManagerCookie
	va    AS.VA
}

type FunctionExplorer struct {
	emu     *E.Emulator
	sman    *E.SnapshotManager
	todo    []todoPath
	hits    map[AS.VA]bool
	startSp AS.VA
	ac      artifacts.ArtifactCollection
}

func (s *FunctionExplorer) pushState(va AS.VA) error {
	here, e := s.sman.Push()
	check(e)
	s.todo = append(s.todo, todoPath{state: here, va: va})
	return nil
}

func (s *FunctionExplorer) popState() error {
	if len(s.todo) == 0 {
		// TODO: handle a real error
		panic("no paths to explore")
	}
	path := s.todo[len(s.todo)-1]
	s.todo = s.todo[1:]
	log.Printf("exploring path %s: va=0x%x", path.state, path.va)
	check(s.sman.RevertUntil(path.state))
	s.emu.SetInstructionPointer(path.va)
	return nil
}

func (s *FunctionExplorer) hasExploredThisAddressBefore() bool {
	_, ok := s.hits[s.emu.GetInstructionPointer()]
	return ok
}

func (s *FunctionExplorer) markThisAddressExplored() error {
	s.hits[s.emu.GetInstructionPointer()] = true
	return nil
}

func (s *FunctionExplorer) tracePc() error {
	str, _, e := s.emu.FormatAddress(s.emu.GetInstructionPointer())
	check(e)
	color.Set(color.FgHiBlack)
	log.Printf("ip:" + str)
	color.Unset()
	return nil
}

func (s *FunctionExplorer) handleRet(insn gapstone.Instruction) error {
	log.Printf("returning, done.")
	afterSp := s.emu.GetStackPointer()
	stackDelta := uint64(afterSp) - uint64(s.startSp)
	log.Printf("stack delta: 0x%x", stackDelta)
	return nil
}

func (s *FunctionExplorer) handleConditionalJump(insn gapstone.Instruction) error {
	// TODO: make emu aware!
	targets, e := dis.GetJumpTargets(insn)
	check(e)
	if len(targets) < 2 {
		// TODO: by definition, a conditional jump should have at least two cases...
		panic("len(targets) < 2")
	}

	nextPc := targets[0]
	for _, target := range targets[1:] {
		log.Printf("other target: 0x%x", target)
		check(s.pushState(target.To))
	}
	s.emu.SetInstructionPointer(nextPc.To)
	return nil
}

func (s *FunctionExplorer) handleCall(insn gapstone.Instruction) error {
	// TODO: try to resolve imports before blindly emulating
	callPc, e := GetNextInstructionPointer(s.emu, s.sman)
	if e == nil {
		log.Printf("  call target: 0x%x", callPc)
	}
	s.ac.AddCallXref(artifacts.CallCrossReference{s.emu.GetInstructionPointer(), callPc})

	nextPc := AS.VA(uint64(s.emu.GetInstructionPointer()) + uint64(insn.Size))
	s.emu.SetInstructionPointer(nextPc)

	// TODO: need to detect calling convention, and in the case of stdcall,
	//   cleanup the stack

	return nil
}

func (s *FunctionExplorer) handleGeneralInstruction(insn gapstone.Instruction) error {
	return s.emu.StepOver()
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
func (dora *Dora) ExploreFunction(va AS.VA) error {
	emu, e := E.New(dora.ws)
	check(e)
	defer emu.Close()

	sman, e := E.NewSnapshotManager(emu)
	check(e)
	defer sman.Close()

	ex := &FunctionExplorer{
		emu:     emu,
		sman:    sman,
		todo:    []todoPath{},
		hits:    make(map[AS.VA]bool),
		startSp: emu.GetStackPointer(),
		ac:      dora.ac,
	}

	bbStart := va
	emu.SetInstructionPointer(va)
	check(e)

	// TODO: how to disable these while on an excursion?
	rh, e := emu.HookMemRead(func(access int, addr AS.VA, size int, value int64) {
		// TODO: filter out stack references
		dora.ac.AddMemoryReadXref(artifacts.MemoryReadCrossReference{emu.GetInstructionPointer(), addr})
	})
	check(e)
	defer rh.Close()

	wh, e := emu.HookMemWrite(func(access int, addr AS.VA, size int, value int64) {
		// TODO: filter out stack references
		dora.ac.AddMemoryWriteXref(artifacts.MemoryWriteCrossReference{emu.GetInstructionPointer(), addr})
	})
	check(e)
	defer wh.Close()

	check(ex.pushState(va))

	// TODO: don't reach
	for len(ex.todo) > 0 {
		check(ex.popState())
		for {
			if ex.hasExploredThisAddressBefore() {
				break
			}

			ex.tracePc()

			insn, e := ex.emu.GetCurrentInstruction()
			check(e)

			check(ex.markThisAddressExplored())

			if isBBEnd(insn) {
				e := dora.ac.AddBasicBlock(artifacts.BasicBlock{Start: bbStart, End: emu.GetInstructionPointer()})
				check(e)
			}

			beforePc := ex.emu.GetInstructionPointer()
			if dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_RET) ||
				dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_IRET) {
				check(ex.handleRet(insn))
				break
			} else if dis.IsConditionalJump(insn) {
				check(ex.handleConditionalJump(insn))
			} else if dis.DoesInstructionHaveGroup(insn, gapstone.X86_GRP_CALL) {
				check(ex.handleCall(insn))
			} else {
				e := ex.handleGeneralInstruction(insn)
				if e != nil {
					log.Printf("error: %s", e.Error())
					break
				}
			}

			// TODO: fetch stack read/write set for arg/variable detection
			// TODO: fetch reg read/write set for arg detection

			afterPc := emu.GetInstructionPointer()
			if isBBEnd(insn) {
				bbStart = emu.GetInstructionPointer()
				// TODO: use correct jump type
				e := dora.ac.AddJumpXref(
					artifacts.JumpCrossReference{
						CrossReference: artifacts.CrossReference{
							From: beforePc,
							To:   afterPc,
						},
						Type: artifacts.JumpTypeUncond})
				check(e)
			}
		}
	}

	return nil
}
