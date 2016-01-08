package mem_persistence

import (
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
	//	"log"
)

type MemPersistence struct {
	addressDataS map[P.AddressDataType]map[AS.VA]map[P.AddressDataKeyS]string
	addressDataI map[P.AddressDataType]map[AS.VA]map[P.AddressDataKeyI]int64

	edgeDataS map[P.EdgeDataType]map[AS.VA]map[AS.VA]map[P.EdgeDataKeyS]string
	edgeDataI map[P.EdgeDataType]map[AS.VA]map[AS.VA]map[P.EdgeDataKeyI]int64
}

// New constructs a new MemPersistence instance
func New() (*MemPersistence, error) {
	return &MemPersistence{
		addressDataS: make(map[P.AddressDataType]map[AS.VA]map[P.AddressDataKeyS]string),
		addressDataI: make(map[P.AddressDataType]map[AS.VA]map[P.AddressDataKeyI]int64),
		edgeDataS:    make(map[P.EdgeDataType]map[AS.VA]map[AS.VA]map[P.EdgeDataKeyS]string),
		edgeDataI:    make(map[P.EdgeDataType]map[AS.VA]map[AS.VA]map[P.EdgeDataKeyI]int64),
	}, nil
}

/** MemPersistence implements interface Persistence **/

func (m *MemPersistence) SetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS, value string) error {
	vamap, ok := m.addressDataS[atype]
	if !ok {
		vamap = make(map[AS.VA]map[P.AddressDataKeyS]string)
		m.addressDataS[atype] = vamap
	}
	keymap, ok := vamap[va]
	if !ok {
		keymap = make(map[P.AddressDataKeyS]string)
		vamap[va] = keymap
	}
	keymap[key] = value
	return nil
}

func (m *MemPersistence) DelAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) error {
	vamap, ok := m.addressDataS[atype]
	if !ok {
		return nil
	}
	keymap, ok := vamap[va]
	if !ok {
		return nil
	}
	delete(keymap, key)
	return nil
}

func (m *MemPersistence) GetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) (string, error) {
	vamap, ok := m.addressDataS[atype]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	keymap, ok := vamap[va]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	value, ok := keymap[key]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	return value, nil
}

func (m *MemPersistence) GetAddressValueStrings(atype P.AddressDataType, va AS.VA) ([]P.AddressValueString, error) {
	var ret []P.AddressValueString

	vamap, ok := m.addressDataS[atype]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	keymap, ok := vamap[va]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	ret = make([]P.AddressValueString, 0, len(keymap))
	for k, v := range keymap {
		ret = append(ret, P.AddressValueString{
			Type:  atype,
			VA:    va,
			Key:   k,
			Value: v,
		})
	}
	return ret, nil
}

func (m *MemPersistence) SetAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI, value int64) error {

	vamap, ok := m.addressDataI[atype]
	if !ok {
		vamap = make(map[AS.VA]map[P.AddressDataKeyI]int64)
		m.addressDataI[atype] = vamap
	}
	keymap, ok := vamap[va]
	if !ok {
		keymap = make(map[P.AddressDataKeyI]int64)
		vamap[va] = keymap
	}
	keymap[key] = value
	return nil
}

func (m *MemPersistence) DelAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) error {
	vamap, ok := m.addressDataI[atype]
	if !ok {
		return nil
	}
	keymap, ok := vamap[va]
	if !ok {
		return nil
	}
	delete(keymap, key)
	return nil
}

func (m *MemPersistence) GetAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) (int64, error) {
	vamap, ok := m.addressDataI[atype]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	keymap, ok := vamap[va]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	value, ok := keymap[key]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	return value, nil
}

func (m *MemPersistence) GetAddressValueNumbers(atype P.AddressDataType, va AS.VA) ([]P.AddressValueNumber, error) {
	var ret []P.AddressValueNumber

	vamap, ok := m.addressDataI[atype]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	keymap, ok := vamap[va]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	ret = make([]P.AddressValueNumber, 0, len(keymap))
	for k, v := range keymap {
		ret = append(ret, P.AddressValueNumber{
			Type:  atype,
			VA:    va,
			Key:   k,
			Value: v,
		})
	}
	return ret, nil
}

func (m *MemPersistence) SetEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS, value string) error {

	frommap, ok := m.edgeDataS[etype]
	if !ok {
		frommap = make(map[AS.VA]map[AS.VA]map[P.EdgeDataKeyS]string)
		m.edgeDataS[etype] = frommap
	}
	tomap, ok := frommap[from]
	if !ok {
		tomap = make(map[AS.VA]map[P.EdgeDataKeyS]string)
		frommap[from] = tomap
	}
	keymap, ok := tomap[to]
	if !ok {
		keymap = make(map[P.EdgeDataKeyS]string)
		tomap[to] = keymap
	}
	keymap[key] = value
	return nil
}

func (m *MemPersistence) DelEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) error {

	frommap, ok := m.edgeDataS[etype]
	if !ok {
		return nil
	}
	tomap, ok := frommap[from]
	if !ok {
		return nil
	}
	keymap, ok := tomap[to]
	if !ok {
		return nil
	}
	delete(keymap, key)
	return nil
}

func (m *MemPersistence) GetEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) (string, error) {

	frommap, ok := m.edgeDataS[etype]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	tomap, ok := frommap[from]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	keymap, ok := tomap[to]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	value, ok := keymap[key]
	if !ok {
		return "", P.ErrKeyDoesNotExist
	}
	return value, nil
}

func (m *MemPersistence) GetEdgeValueStrings(etype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueString, error) {
	var ret []P.EdgeValueString

	frommap, ok := m.edgeDataS[etype]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	tomap, ok := frommap[from]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	keymap, ok := tomap[to]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	ret = make([]P.EdgeValueString, 0, len(keymap))
	for k, v := range keymap {
		ret = append(ret, P.EdgeValueString{
			Type:  etype,
			From:  from,
			To:    to,
			Key:   k,
			Value: v,
		})
	}
	return ret, nil
}

func (m *MemPersistence) SetEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI, value int64) error {

	frommap, ok := m.edgeDataI[etype]
	if !ok {
		frommap = make(map[AS.VA]map[AS.VA]map[P.EdgeDataKeyI]int64)
		m.edgeDataI[etype] = frommap
	}
	tomap, ok := frommap[from]
	if !ok {
		tomap = make(map[AS.VA]map[P.EdgeDataKeyI]int64)
		frommap[from] = tomap
	}
	keymap, ok := tomap[to]
	if !ok {
		keymap = make(map[P.EdgeDataKeyI]int64)
		tomap[to] = keymap
	}
	keymap[key] = value
	return nil
}

func (m *MemPersistence) DelEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) error {

	frommap, ok := m.edgeDataI[etype]
	if !ok {
		return nil
	}
	tomap, ok := frommap[from]
	if !ok {
		return nil
	}
	keymap, ok := tomap[to]
	if !ok {
		return nil
	}
	delete(keymap, key)
	return nil
}

func (m *MemPersistence) GetEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) (int64, error) {

	frommap, ok := m.edgeDataI[etype]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	tomap, ok := frommap[from]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	keymap, ok := tomap[to]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	value, ok := keymap[key]
	if !ok {
		return 0, P.ErrKeyDoesNotExist
	}
	return value, nil
}

func (m *MemPersistence) GetEdgeValueNumbers(etype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueNumber, error) {
	var ret []P.EdgeValueNumber

	frommap, ok := m.edgeDataI[etype]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	tomap, ok := frommap[from]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	keymap, ok := tomap[to]
	if !ok {
		return ret, P.ErrKeyDoesNotExist
	}
	ret = make([]P.EdgeValueNumber, 0, len(keymap))
	for k, v := range keymap {
		ret = append(ret, P.EdgeValueNumber{
			Type:  etype,
			From:  from,
			To:    to,
			Key:   k,
			Value: v,
		})
	}
	return ret, nil
}
