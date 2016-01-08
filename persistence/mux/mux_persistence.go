package mux_persistence

import (
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
)

type MuxPersistence struct {
	others []P.Persistence
}

// New constructs a new MuxPersistence instance
func New(others ...P.Persistence) (*MuxPersistence, error) {
	return &MuxPersistence{
		others: others,
	}, nil
}

/** MuxPersistence implements interface Persistence **/

func (m *MuxPersistence) SetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS, value string) error {
	var ret error
	for _, p := range m.others {
		e := p.SetAddressValueString(atype, va, key, value)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) DelAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) error {
	var ret error
	for _, p := range m.others {
		e := p.DelAddressValueString(atype, va, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) GetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) (string, error) {
	var ret error
	for _, p := range m.others {
		v, e := p.GetAddressValueString(atype, va, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return "", ret
}

func (m *MuxPersistence) GetAddressValueStrings(atype P.AddressDataType, va AS.VA) ([]P.AddressValueString, error) {
	var r []P.AddressValueString
	var ret error
	for _, p := range m.others {
		v, e := p.GetAddressValueStrings(atype, va)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return r, ret
}

func (m *MuxPersistence) SetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI, value string) error {
	var ret error
	for _, p := range m.others {
		e := p.SetAddressValueNumber(atype, va, key, value)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) DelAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) error {
	var ret error
	for _, p := range m.others {
		e := p.DelAddressValueNumber(atype, va, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) GetAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) (string, error) {
	var ret error
	for _, p := range m.others {
		v, e := p.GetAddressValueNumber(atype, va, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return "", ret
}

func (m *MuxPersistence) GetAddressValueNumbers(atype P.AddressDataType, va AS.VA) ([]P.AddressValueNumber, error) {
	var r []P.AddressValueNumber
	var ret error
	for _, p := range m.others {
		v, e := p.GetAddressValueNumbers(atype, va)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return r, ret
}

func (m *MuxPersistence) SetEdgeValueString(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS, value string) error {
	var ret error
	for _, p := range m.others {
		e := p.SetEdgeValueString(atype, from, to, key, value)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) DelEdgeValueString(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) error {
	var ret error
	for _, p := range m.others {
		e := p.DelEdgeValueString(atype, from, to, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) GetEdgeValueString(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) (string, error) {
	var ret error
	for _, p := range m.others {
		v, e := p.GetEdgeValueString(atype, from, to, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return "", ret
}

func (m *MuxPersistence) GetEdgeValueStrings(atype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueString, error) {
	var r []P.EdgeValueString
	var ret error
	for _, p := range m.others {
		v, e := p.GetEdgeValueStrings(atype, from, to)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return r, ret
}

func (m *MuxPersistence) SetEdgeValueString(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI, value string) error {
	var ret error
	for _, p := range m.others {
		e := p.SetEdgeValueNumber(atype, from, to, key, value)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) DelEdgeValueNumber(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) error {
	var ret error
	for _, p := range m.others {
		e := p.DelEdgeValueNumber(atype, from, to, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
	}
	return nil
}

func (m *MuxPersistence) GetEdgeValueNumber(atype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) (string, error) {
	var ret error
	for _, p := range m.others {
		v, e := p.GetEdgeValueNumber(atype, from, to, key)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return "", ret
}

func (m *MuxPersistence) GetEdgeValueNumbers(atype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueNumber, error) {
	var r []P.EdgeValueNumber
	var ret error
	for _, p := range m.others {
		v, e := p.GetEdgeValueNumbers(atype, from, to)
		if e != P.ErrNotImplemented && e != nil {
			ret = e
		}
		if e != P.ErrNotImplemented {
			return v, nil
		}
	}
	return r, ret
}
