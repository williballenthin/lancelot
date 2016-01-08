package artifacts

import (
	AS "github.com/williballenthin/Lancelot/address_space"
	"log"
)

type AddressDataType uint

const (
	FunctionData = iota
	BasicBlockData
)

type AddressDataKeyS uint

const (
	FunctionName = iota
)

type AddressDataKeyI uint

const (
	FunctionStackDelta = iota
)

type AddressDataName struct {
	Type AddressDataType
	VA   AS.VA
	Name string
}

type AddressValueString struct {
	Type  AddressDataType
	VA    AS.VA
	Name  string
	Value string
}

type AddressValueNumber struct {
	Type  AddressDataType
	VA    AS.VA
	Name  string
	Value int64
}

type EdgeDataType uint

const (
	XrefBranchType = iota
)

type EdgeDataKeyS uint

const (
	XrefName = iota
)

type EdgeDataKeyI uint

const (
	XrefWeight = iota
)

type EdgeDataName struct {
	Type EdgeDataType
	From AS.VA
	To   AS.VA
	Name string
}

type EdgeValueString struct {
	Type  EdgeDataType
	From  AS.VA
	To    AS.VA
	Name  string
	Value string
}

type EdgeValueNumber struct {
	Type  EdgeDataType
	From  AS.VA
	To    AS.VA
	Name  string
	Value int64
}

type Persistence interface {
	AddAddressName(atype AddressDataType, va AS.VA, name string) error
	DelAddressName(atype AddressDataType, va AS.VA) error
	GetAddressName(atype AddressDataType, va AS.VA) (string, error)
	GetAddressNames(va AS.VA) ([]AddressDataName, error)

	AddAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS, value string) error
	DelAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS) error
	GetAddressValueString(atype AddressDataType, va AS.VA, key AddressDataKeyS) (string, error)
	GetAddressValueStrings(atype AddressDataType, va AS.VA, key AddressDataKeyS) ([]AddressValueString, error)

	AddAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI, value int64) error
	DelAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI) error
	GetAddressValueNumber(atype AddressDataType, va AS.VA, key AddressDataKeyI) (int64, error)
	GetAddressValueNumbers(atype AddressDataType, va AS.VA, key AddressDataKeyI) ([]AddressValueNumber, error)

	AddEdgeName(atype EdgeDataType, va AS.VA, name string) error
	DelEdgeName(atype EdgeDataType, va AS.VA) error
	GetEdgeName(atype EdgeDataType, va AS.VA) (string, error)
	GetEdgeNames(va AS.VA) ([]EdgeDataName, error)

	AddEdgeValueString(atype EdgeDataType, va AS.VA, key EdgeDataKeyS, value string) error
	DelEdgeValueString(atype EdgeDataType, va AS.VA, key EdgeDataKeyS) error
	GetEdgeValueString(atype EdgeDataType, va AS.VA, key EdgeDataKeyS) (string, error)
	GetEdgeValueStrings(atype EdgeDataType, va AS.VA, key EdgeDataKeyS) ([]EdgeValueString, error)

	AddEdgeValueNumber(atype EdgeDataType, va AS.VA, key EdgeDataKeyI, value int64) error
	DelEdgeValueNumber(atype EdgeDataType, va AS.VA, key EdgeDataKeyI) error
	GetEdgeValueNumber(atype EdgeDataType, va AS.VA, key EdgeDataKeyI) (int64, error)
	GetEdgeValueNumbers(atype EdgeDataType, va AS.VA, key EdgeDataKeyI) ([]EdgeValueNumber, error)
}

// usage:
// var p *Persistence
// p.AddAddressName(FunctionData, fva, "sub_401000")
// p.GetAddressName(FunctionData, fva) --> "sub_401000"
//
// p.AddAddressValueNumber(FunctionData, fva, FunctionStackDelta, 0xC)
// p.GetAddressValueNumber(FunctionData, fva, FunctionStackDelta) --> 0xC
