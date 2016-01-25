package persistence

import (
	"errors"
	AS "github.com/williballenthin/Lancelot/address_space"
)

// ErrNotImplemented should be returned by implementors of Persistence
//  that don't support some operation.
var ErrNotImplemented = errors.New("Method not implemented")

type AddressDataType uint

type AddressDataKeyS uint

type AddressDataKeyI uint

type AddressValueString struct {
	Type  AddressDataType
	VA    AS.VA
	Key   AddressDataKeyS
	Value string
}

type AddressValueNumber struct {
	Type  AddressDataType
	VA    AS.VA
	Key   AddressDataKeyI
	Value int64
}

type EdgeDataType uint

type EdgeDataKeyS uint

type EdgeDataKeyI uint

type EdgeValueString struct {
	Type  EdgeDataType
	From  AS.VA
	To    AS.VA
	Key   EdgeDataKeyS
	Value string
}

type EdgeValueNumber struct {
	Type  EdgeDataType
	From  AS.VA
	To    AS.VA
	Key   EdgeDataKeyI
	Value int64
}

var ErrKeyDoesNotExist = errors.New("The requested key does not exist at the requested location")

type Persistence interface {
	// stomps on existing value
	SetAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS, value string) error
	// no error if key does not exist
	DelAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS) error
	// returns ErrKeyDoesNotExist if any part of the query fails
	GetAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS) (string, error)
	// returns the empty list and ErrKeyDoesNotExist if any part of the query fails
	GetAddressValueStrings(atype AddressDataType, va AS.VA) ([]AddressValueString, error)

	// stomps on existing value
	SetAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI, value int64) error
	// no error if key does not exist
	DelAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI) error
	// returns ErrKeyDoesNotExist if any part of the query fails
	GetAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI) (int64, error)
	// returns the empty list and ErrKeyDoesNotExist if any part of the query fails
	GetAddressValueNumbers(atype AddressDataType, va AS.VA) ([]AddressValueNumber, error)

	// stomps on existing value
	SetEdgeValueString(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyS, value string) error
	// no error if key does not exist
	DelEdgeValueString(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyS) error
	// returns ErrKeyDoesNotExist if any part of the query fails
	GetEdgeValueString(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyS) (string, error)
	// returns the empty list and ErrKeyDoesNotExist if any part of the query fails
	GetEdgeValueStrings(atype EdgeDataType, from AS.VA, to AS.VA) ([]EdgeValueString, error)

	GetEdgesFrom(atype EdgeDataType, from AS.VA) ([]AS.VA, error)
	GetEdgesTo(atype EdgeDataType, to AS.VA) ([]AS.VA, error)

	// stomps on existing value
	SetEdgeValueNumber(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyI, value int64) error
	// no error if key does not exist
	DelEdgeValueNumber(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyI) error
	// returns ErrKeyDoesNotExist if any part of the query fails
	GetEdgeValueNumber(atype EdgeDataType, from AS.VA, to AS.VA, key EdgeDataKeyI) (int64, error)
	// returns the empty list and ErrKeyDoesNotExist if any part of the query fails
	GetEdgeValueNumbers(atype EdgeDataType, from AS.VA, to AS.VA) ([]EdgeValueNumber, error)
}

// usage:
// var p *Persistence
// p.AddAddressValueString(FunctionData, fva, FunctionName, "sub_401000")
// p.GetAddressValueString(FunctionData, fva, FunctionName) --> "sub_401000"
//
// p.AddAddressValueNumber(FunctionData, fva, FunctionStackDelta, 0xC)
// p.GetAddressValueNumber(FunctionData, fva, FunctionStackDelta) --> 0xC
