package dora

import (
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

func (dora *Dora) ExploreFunction(va W.VA) error {
	emu, e := dora.ws.GetEmulator()
	check(e)
	defer emu.Close()

	emu.SetInstructionPointer(va)
	check(e)

	e = emu.RunTo(W.VA(0x0))
	if e != nil {
		log.Printf("error: %s", e.Error())
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
