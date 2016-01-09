package persistence

type LocationType int64

const (
	LocationUnused LocationType = iota
	LocationFunction
	LocationBasicBlock
	LocationString
	LocationUnknown
)

func (l LocationType) String() string {
	switch l {
	case LocationFunction:
		return "LocationFunction"
	case LocationBasicBlock:
		return "LocationBasicBlock"
	case LocationString:
		return "LocationString"
	default:
		panic("unknown type")
	}
}

// AddressDataType
const (
	AddressDataUnused AddressDataType = iota
	LocationData
	FunctionData
	BasicBlockData
)

func (l AddressDataType) String() string {
	switch l {
	case LocationData:
		return "LocationData"
	case FunctionData:
		return "FunctionData"
	case BasicBlockData:
		return "BasicBlock"
	default:
		panic("unknown type")
	}
}

// AddressDataKeyString
const (
	KeyUnusedS AddressDataKeyS = iota
	FunctionName
)

func (l AddressDataKeyS) String() string {
	switch l {
	case FunctionName:
		return "FunctionName"
	default:
		panic("unknown type")
	}
}

// AddressDataKeyNumber
const (
	KeyUnusedI AddressDataKeyI = iota
	FunctionStackDelta
	TypeOfLocation
)

func (l AddressDataKeyI) String() string {
	switch l {
	case FunctionStackDelta:
		return "FunctionStackDelta"
	case TypeOfLocation:
		return "TypeOfLocation"
	default:
		panic("unknown type")
	}
}

// EdgeDataType
const (
	EdgeDataUnused EdgeDataType = iota
	// from basic block to basic block
	CodeXrefData
	// from instruction to VA (mem read/write),
	// or VA to VA (pointer
	DataXrefData
	// from function to function
	CallGraphData
)

func (l EdgeDataType) String() string {
	switch l {
	case CodeXrefData:
		return "CodeXrefData"
	case DataXrefData:
		return "DataXrefData"
	case CallGraphData:
		return "CallGraphData"
	default:
		panic("unknown type")
	}
}

// EdgeDataKeyString
const (
	EdgeKeyUnusedS EdgeDataKeyS = iota
	XrefName
)

func (l EdgeDataKeyS) String() string {
	switch l {
	case XrefName:
		return "XrefName"
	default:
		panic("unknown type")
	}
}

// EdgeDataKeyNumber
const (
	EdgeKeyUnusedI EdgeDataKeyI = iota
	XrefBranchType              // this some fake value so we can test
	XrefJumpType
)

func (l EdgeDataKeyI) String() string {
	switch l {
	case XrefBranchType:
		return "XrefBranchType"
	case XrefJumpType:
		return "XrefJumpType"
	default:
		panic("unknown type")
	}
}

type JumpType int64

// JumpType defines the possible types of intra-function edges.
const (
	JumpTypeUnused JumpType = iota
	// JumpTypeCondTrue is the JumpType that represents the True
	//  edge of a conditional branch.
	JumpTypeCondTrue
	// JumpTypeCondFalse is the JumpType that represents the False
	//  edge of a conditional branch.
	JumpTypeCondFalse
	// JumpTypeUncond is the JumpType that represents the edge of
	//  an unconditional branch.
	JumpTypeUncond
	JumpTypeSwitch
)

func (t JumpType) String() string {
	switch t {
	case JumpTypeCondTrue:
		return "JumpTypeCondTrue"
	case JumpTypeCondFalse:
		return "JumpTypeCondFalse"
	case JumpTypeUncond:
		return "JumpTypeUncond"
	case JumpTypeSwitch:
		return "JumpTypeSwitch"
	default:
		panic("unexpected JumpType")
	}
}
