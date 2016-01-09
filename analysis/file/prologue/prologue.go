package prologue_analysis

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	AS "github.com/williballenthin/Lancelot/address_space"
	W "github.com/williballenthin/Lancelot/workspace"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type PrologueAnalysis struct {
	ws *W.Workspace
}

func New(ws *W.Workspace) (*PrologueAnalysis, error) {
	return &PrologueAnalysis{
		ws: ws,
	}, nil
}

// findAll locates all instances of the given separator in
//  the given byteslice and returns the RVAs relative to the
//  start of the slice.
func findAll(d []byte, sep []byte) ([]AS.RVA, error) {
	var offset uint64
	ret := make([]AS.RVA, 0, 100)
	for {
		i := bytes.Index(d, sep)
		if i == -1 {
			break
		}

		ret = append(ret, AS.RVA(uint64(i)+offset))

		if i+len(sep) > len(d) {
			break
		}
		d = d[i+len(sep):]
		offset += uint64(i + len(sep))
	}
	return ret, nil
}

// findPrologues locates all instances of common x86 function
//   prologues in the given byteslice.
func findPrologues(d []byte) ([]AS.RVA, error) {
	ret := make([]AS.RVA, 0, 100)
	bare := make(map[AS.RVA]bool)

	// first, find prologues with hotpatch region
	hits, e := findAll(d, []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC}) // mov edi, edi; push ebp; mov ebp, esp
	check(e)

	// index the "bare" prologue start for future overlap query
	ret = append(ret, hits...)
	for _, hit := range hits {
		bare[AS.RVA(uint64(hit)+0x2)] = true
	}

	// now, find prologues without hotpatch region
	hits, e = findAll(d, []byte{0x55, 0x8B, 0xEC}) // push ebp; mov ebp, esp
	check(e)

	// and ensure they don't overlap with the hotpatchable prologues
	for _, hit := range hits {
		if _, ok := bare[hit]; ok {
			continue
		}
		ret = append(ret, hit)
	}

	return ret, nil
}

/** PrologueAnalysis implements FileAnalysis interface **/
func (a *PrologueAnalysis) AnalyzeAll() error {

	// search for prologues in each memory region, queue them
	//  up as functions to analyze
	mmaps, e := a.ws.GetMaps()
	check(e)
	for _, mmap := range mmaps {
		d, e := a.ws.MemRead(mmap.Address, mmap.Length)
		check(e)

		fns, e := findPrologues(d)
		check(e)

		for _, fn := range fns {
			fva := fn.VA(mmap.Address)
			a.ws.MakeFunction(fva)
			logrus.Debug("function prologue analysis: found function: %s", fva)
		}
	}
	return nil
}

func (a *PrologueAnalysis) Priority() uint {
	return 75
}
