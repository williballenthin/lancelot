package address_space

import (
	"github.com/Sirupsen/logrus"
)

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
		logrus.Debugf("reverting dirty page: %s", k)
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
	pageVA := VA(roundDownToPage(uint64(va)))
	logrus.Debugf("marking dirty: %s page: %s", va, pageVA)
	// probe the page to ensure it exists
	_, e := snap.currentAddressSpace.MemRead(pageVA, 1)
	if e == nil {
		snap.dirtyPageNumbers[pageVA] = true
	}
	return nil
}

// TODO: MemorySnapshot.Merge, that syncs dirtyPages from src to dst MemorySnapshots
