package workspace

import (
	"errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

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

// An address space backed by a Unicorn instance.
// Easy to implement because Unicorn already does the hard work.
type UnicornAddressSpace struct {
	u    uc.Unicorn
	maps []MemoryRegion
}

func NewUnicornAddressSpace(arch Arch, mode Mode) (*UnicornAddressSpace, error) {
	if arch != ARCH_X86 {
		return nil, InvalidArchError
	}
	if !(mode == MODE_32 || mode == MODE_64) {
		return nil, InvalidModeError
	}

	var u uc.Unicorn
	var e error
	if mode == MODE_32 {
		u, e = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
	} else if mode == MODE_64 {
		u, e = uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
	}
	if e != nil {
		return nil, e
	}
	return &UnicornAddressSpace{
		u:    u,
		maps: make([]MemoryRegion, 0),
	}, nil
}

func (uas *UnicornAddressSpace) MemRead(va VA, length uint64) ([]byte, error) {
	return uas.u.MemRead(uint64(va), length)
}

func (uas *UnicornAddressSpace) MemWrite(va VA, data []byte) error {
	return uas.u.MemWrite(uint64(va), data)
}

func (uas *UnicornAddressSpace) MemMap(va VA, length uint64, name string) error {
	e := uas.u.MemMap(uint64(va), length)
	if e != nil {
		return e
	}

	uas.maps = append(uas.maps, MemoryRegion{va, length, name})

	return nil
}

var InvalidArgumentError = errors.New("Invalid argument")

func (uas *UnicornAddressSpace) MemUnmap(va VA, length uint64) error {
	e := uas.u.MemUnmap(uint64(va), length)
	if e != nil {
		return e
	}

	for i, region := range uas.maps {
		if region.Address == va {
			if region.Length != length {
				return InvalidArgumentError
			}

			uas.maps = append(uas.maps[:i], uas.maps[i+1:]...)
			break
		}
	}

	return nil
}

func (uas *UnicornAddressSpace) GetMaps() ([]MemoryRegion, error) {
	ret := make([]MemoryRegion, len(uas.maps))
	copy(ret, uas.maps)
	return ret, nil
}

func (uas *UnicornAddressSpace) Close() error {
	//uas.u.Close()
	return nil
}

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

/************************************************* */

func CopyAddressSpace(dest AddressSpace, src AddressSpace) error {
	maps, e := src.GetMaps()
	check(e)

	for _, m := range maps {
		e := dest.MemMap(m.Address, m.Length, m.Name)
		check(e)
		if e != nil {
			// this is bad, because some data may already have been mapped.
			// BUG: should unmap anything we mapped before this failure.
			return e
		}

		d, e := src.MemRead(m.Address, m.Length)
		check(e)
		if e != nil {
			// BUG: should unmap anything we mapped before this failure.
			return e
		}

		e = dest.MemWrite(m.Address, d)
		check(e)
		if e != nil {
			// BUG: should unmap anything we mapped before this failure.
			return e
		}
	}

	return nil
}

const PAGE_SIZE = 0x1000

type MemorySnapshot struct {
	// the data that exists at the time of the snapshot
	currentAddressSpace AddressSpace
	// the changes since the snapshot was taken
	dirtyPageNumbers     map[VA]bool
	newlyMappedRegions   []MemoryRegion
	newlyUnmappedRegions []MemoryRegion
}

func CreateMemorySnapshot(as AddressSpace) (*MemorySnapshot, error) {
	newas, e := NewSimpleAddressSpace()
	check(e)
	if e != nil {
		return nil, e
	}

	e = CopyAddressSpace(newas, as)
	check(e)
	if e != nil {
		return nil, e
	}

	return &MemorySnapshot{
		currentAddressSpace:  newas,
		dirtyPageNumbers:     make(map[VA]bool),
		newlyMappedRegions:   make([]MemoryRegion, 0),
		newlyUnmappedRegions: make([]MemoryRegion, 0),
	}, nil
}

func (snap *MemorySnapshot) Clone() (*MemorySnapshot, error) {
	newas, e := NewSimpleAddressSpace()
	check(e)
	if e != nil {
		return nil, e
	}

	e = CopyAddressSpace(newas, snap.currentAddressSpace)
	check(e)
	if e != nil {
		return nil, e
	}

	dirtyPageNumbers := make(map[VA]bool)
	for k, v := range snap.dirtyPageNumbers {
		dirtyPageNumbers[k] = v
	}

	newlyMappedRegions := make([]MemoryRegion, 0)
	copy(newlyMappedRegions, snap.newlyMappedRegions)

	newlyUnmappedRegions := make([]MemoryRegion, 0)
	copy(newlyUnmappedRegions, snap.newlyUnmappedRegions)

	return &MemorySnapshot{
		currentAddressSpace:  newas,
		dirtyPageNumbers:     dirtyPageNumbers,
		newlyMappedRegions:   newlyMappedRegions,
		newlyUnmappedRegions: newlyUnmappedRegions,
	}, nil
}

// Restore an address space from the outstanding changes in this snapshot.
func (snap *MemorySnapshot) RevertAddressSpace(as AddressSpace) error {
	for k, _ := range snap.dirtyPageNumbers {
		d, e := snap.currentAddressSpace.MemRead(k, PAGE_SIZE)
		check(e)
		if e != nil {
			// BUG: transaction in progress. should undo any changes.
			return e
		}
		e = as.MemWrite(k, d)
		check(e)
		if e != nil {
			// BUG: transaction in progress. should undo any changes.
			return e
		}
	}

	return nil
}

// Forgets about all outstanding changes to this snapshot.
func (snap *MemorySnapshot) Revert() error {
	snap.dirtyPageNumbers = make(map[VA]bool)
	snap.newlyMappedRegions = make([]MemoryRegion, 0)
	snap.newlyUnmappedRegions = make([]MemoryRegion, 0)
	return nil
}

// Update the current memory in this snapshot from the outstanding changes in an address space.
func (snap *MemorySnapshot) CommitFromAddressSpace(as AddressSpace) error {
	for k, _ := range snap.dirtyPageNumbers {
		d, e := as.MemRead(k, PAGE_SIZE)
		check(e)
		if e != nil {
			// BUG: transaction in progress. should undo any changes.
			return e
		}
		e = snap.currentAddressSpace.MemWrite(k, d)
		check(e)
		if e != nil {
			// BUG: transaction in progress. should undo any changes.
			return e
		}
	}

	return nil
}

func roundDown(i uint64, base uint64) uint64 {
	if i%base == 0x0 {
		return i
	} else {
		return i - (i % base)
	}
}

func roundDownToPage(i uint64) uint64 {
	return roundDown(i, PAGE_SIZE)
}

func (snap *MemorySnapshot) MarkDirty(va VA) error {
	snap.dirtyPageNumbers[VA(roundDownToPage(uint64(va)))] = true
	return nil
}

// TODO: MemorySnapshot.Merge, that syncs dirtyPages from src to dst MemorySnapshots
