package address_space

import (
	"errors"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type VA uint64
type RVA uint64

func (rva RVA) VA(baseAddress VA) VA {
	return VA(uint64(rva) + uint64(baseAddress))
}

type MemoryRegion struct {
	Address VA
	Length  uint64
	Name    string
}

type AddressSpace interface {
	MemRead(va VA, length uint64) ([]byte, error)
	MemWrite(va VA, data []byte) error
	MemMap(va VA, length uint64, name string) error
	MemUnmap(va VA, length uint64) error
	GetMaps() ([]MemoryRegion, error)
	Close() error
}

var InvalidArgumentError = errors.New("Invalid argument")
var ErrInvalidMemoryWrite error = errors.New("Invalid memory write error")
var ErrInvalidMemoryRead error = errors.New("Invalid memory read error")
var ErrInvalidMemoryExec error = errors.New("Invalid memory exec error")
var ErrUnmappedMemory error = errors.New("Unmapped memory error")
var ErrUnknownMemory error = errors.New("Unknown memory error")

/************************************************** */

// A simple address space implementation that uses byte arrays to represent memory.
type SimpleAddressSpace struct {
	data map[VA][]byte
	maps []MemoryRegion
}

func NewSimpleAddressSpace() (*SimpleAddressSpace, error) {
	return &SimpleAddressSpace{
		data: make(map[VA][]byte, 0),
		maps: make([]MemoryRegion, 0),
	}, nil
}

var MemoryMapOverrun error = errors.New("Memory operation overran memory map")

func (sas *SimpleAddressSpace) findData(va VA, length uint64) ([]byte, error) {
	var region MemoryRegion
	found := false
	for _, m := range sas.maps {
		if va >= m.Address && va < VA(uint64(m.Address)+m.Length) {
			if VA(uint64(va)+length) > VA(uint64(m.Address)+m.Length) {
				// overruns region
				// BUG: what if there are contiguous regions???
				return nil, MemoryMapOverrun
			}
			found = true
			region = m
			break
		}
	}
	if !found {
		return nil, ErrUnmappedMemory
	}
	data := sas.data[region.Address]
	offset := uint64(va) - uint64(region.Address)
	return data[offset : offset+length], nil
}

func (sas *SimpleAddressSpace) MemRead(va VA, length uint64) ([]byte, error) {
	data, e := sas.findData(va, length)
	if e != nil {
		return nil, e
	}
	ret := make([]byte, length)
	copy(ret, data)
	return ret, nil
}

func (sas *SimpleAddressSpace) MemWrite(va VA, data []byte) error {
	ourdata, e := sas.findData(va, uint64(len(data)))
	if e != nil {
		return e
	}
	copy(ourdata, data)
	return nil
}

func (sas *SimpleAddressSpace) MemMap(va VA, length uint64, name string) error {
	// TODO: does not check if map already exists
	// TODO: does not check map alignment
	sas.data[va] = make([]byte, length)
	sas.maps = append(sas.maps, MemoryRegion{va, length, name})
	return nil
}

func (sas *SimpleAddressSpace) MemUnmap(va VA, length uint64) error {
	// TODO: does not check if the map dne
	delete(sas.data, va)
	for i, region := range sas.maps {
		if region.Address == va {
			if region.Length != length {
				return InvalidArgumentError
			}

			sas.maps = append(sas.maps[:i], sas.maps[i+1:]...)
			break
		}
	}

	return nil
}

func (sas *SimpleAddressSpace) GetMaps() ([]MemoryRegion, error) {
	ret := make([]MemoryRegion, len(sas.maps))
	copy(ret, sas.maps)
	return ret, nil
}

func (sas *SimpleAddressSpace) Close() error {
	return nil
}
