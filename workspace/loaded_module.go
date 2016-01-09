package workspace

import (
	"bytes"
	"encoding/binary"
	AS "github.com/williballenthin/Lancelot/address_space"
)

type LinkedSymbol struct {
	ModuleName string
	SymbolName string
}

type ExportedSymbol struct {
	RVA             AS.RVA
	IsForwarded     bool
	ForwardedSymbol LinkedSymbol
}

type LoadedModule struct {
	Name             string
	BaseAddress      AS.VA
	EntryPoint       AS.VA
	Imports          map[AS.RVA]LinkedSymbol
	ExportsByName    map[string]ExportedSymbol
	ExportsByOrdinal map[uint16]ExportedSymbol
}

func (m LoadedModule) VA(rva AS.RVA) AS.VA {
	return rva.VA(m.BaseAddress)
}

// note: rva is relative to the module
func (m LoadedModule) MemRead(ws *Workspace, rva AS.RVA, length uint64) ([]byte, error) {
	return ws.MemRead(m.VA(rva), length)
}

// note: rva is relative to the module
func (m LoadedModule) MemReadPtr(ws *Workspace, rva AS.RVA) (AS.VA, error) {
	if ws.Mode == MODE_32 {
		var data uint32
		d, e := m.MemRead(ws, rva, 0x4)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return AS.VA(uint64(data)), nil
	} else if ws.Mode == MODE_64 {
		var data uint64
		d, e := m.MemRead(ws, rva, 0x8)
		if e != nil {
			return 0, e
		}

		p := bytes.NewBuffer(d)
		binary.Read(p, binary.LittleEndian, &data)
		return AS.VA(uint64(data)), nil
	} else {
		return 0, InvalidModeError
	}
}

// note: rva is relative to the module
func (m LoadedModule) MemReadRva(ws *Workspace, rva AS.RVA) (AS.RVA, error) {
	// AS.RVAs are 32bits even on x64
	var data uint32
	d, e := m.MemRead(ws, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return AS.RVA(uint64(data)), nil
}

// MemReadPeOffset reads a 32bit (even on x64) AS.VA from the given address
//  of the module.
// note: rva is relative to the module
func (m LoadedModule) MemReadPeOffset(ws *Workspace, rva AS.RVA) (AS.VA, error) {
	// PE header offsets are 32bits even on x64
	var data uint32
	d, e := m.MemRead(ws, rva, 0x4)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return AS.VA(uint64(data)), nil
}

// MemReadShort reads a 16bit number (often used for ordinals) from the given
//  address of the module.
// note: rva is relative to the module
func (m LoadedModule) MemReadShort(ws *Workspace, rva AS.RVA) (uint16, error) {
	// PE header offsets are 32bits even on x64
	var data uint16
	d, e := m.MemRead(ws, rva, 0x2)
	if e != nil {
		return 0, e
	}

	p := bytes.NewBuffer(d)
	binary.Read(p, binary.LittleEndian, &data)
	return data, nil
}

// note: rva is relative to the module
func (m LoadedModule) MemWrite(ws *Workspace, rva AS.RVA, data []byte) error {
	return ws.MemWrite(m.VA(rva), data)
}
