package mem_persistence

import (
	P "github.com/williballenthin/Lancelot/persistence"
	//	"log"
	"testing"
)

func TestNew(t *testing.T) {
	m, e := New()
	if e != nil {
		t.Fail()
	}
	if m == nil {
		t.Fail()
	}
}

func TestSAVS(t *testing.T) {
	m, _ := New()
	e := m.SetAddressValueString(P.FunctionData, 0, P.FunctionName, "sub_401000")
	if e != nil {
		t.Fail()
	}
	if m.addressDataS[P.FunctionData][0][P.FunctionName] != "sub_401000" {
		t.Fail()
	}
}

func TestDAVS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(P.FunctionData, 0, P.FunctionName, "sub_401000")
	e := m.DelAddressValueString(P.FunctionData, 0, P.FunctionName)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.addressDataS[P.FunctionData][0][P.FunctionName]; ok {
		t.Fail()
	}
}

func TestGAVS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(P.FunctionData, 0, P.FunctionName, "sub_401000")
	v, e := m.GetAddressValueString(P.FunctionData, 0, P.FunctionName)
	if e != nil {
		t.Fail()
	}
	if v != "sub_401000" {
		t.Fail()
	}
}

func TestGAVSS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(P.FunctionData, 0, P.FunctionName, "sub_401000")
	v, e := m.GetAddressValueStrings(P.FunctionData, 0)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Type != P.FunctionName {
		t.Fail()
	}
	if vv.Value != "sub_401000" {
		t.Fail()
	}
}

func TestSAVI(t *testing.T) {
	m, _ := New()
	e := m.SetAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta, 69)
	if e != nil {
		t.Fail()
	}
	if m.addressDataI[P.FunctionData][0][P.FunctionStackDelta] != 69 {
		t.Fail()
	}
}

func TestDAVI(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta, 69)
	e := m.DelAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.addressDataS[P.FunctionData][0][P.FunctionStackDelta]; ok {
		t.Fail()
	}
}

func TestGAVI(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta, 69)
	v, e := m.GetAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta)
	if e != nil {
		t.Fail()
	}
	if v != 69 {
		t.Fail()
	}
}

func TestGAVIS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(P.FunctionData, 0, P.FunctionStackDelta, 69)
	v, e := m.GetAddressValueNumbers(P.FunctionData, 0)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Type != P.FunctionStackDelta {
		t.Fail()
	}
	if vv.Value != 69 {
		t.Fail()
	}
}

func TestSEVS(t *testing.T) {
	m, _ := New()
	e := m.SetEdgeValueString(P.XrefData, 0, 1, P.XrefName, "sub_401000")
	if e != nil {
		t.Fail()
	}
	if m.edgeDataS[P.XrefData][0][1][P.XrefName] != "sub_401000" {
		t.Fail()
	}
}

func TestDEVS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(P.XrefData, 0, 1, P.XrefName, "sub_401000")
	e := m.DelEdgeValueString(P.XrefData, 0, 1, P.XrefName)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.edgeDataS[P.XrefData][0][1][P.XrefName]; ok {
		t.Fail()
	}
}

func TestGEVS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(P.XrefData, 0, 1, P.XrefName, "sub_401000")
	v, e := m.GetEdgeValueString(P.XrefData, 0, 1, P.XrefName)
	if e != nil {
		t.Fail()
	}
	if v != "sub_401000" {
		t.Fail()
	}
}

func TestGEVSS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(P.XrefData, 0, 1, P.XrefName, "sub_401000")
	v, e := m.GetEdgeValueStrings(P.XrefData, 0, 1)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Type != P.XrefName {
		t.Fail()
	}
	if vv.Value != "sub_401000" {
		t.Fail()
	}
}

func TestSEVI(t *testing.T) {
	m, _ := New()
	e := m.SetEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType, 69)
	if e != nil {
		t.Fail()
	}
	if m.edgeDataI[P.XrefData][0][1][P.XrefBranchType] != 69 {
		t.Fail()
	}
}

func TestDEVI(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType, 69)
	e := m.DelEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.edgeDataS[P.XrefData][0][1][P.XrefBranchType]; ok {
		t.Fail()
	}
}

func TestGEVI(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType, 69)
	v, e := m.GetEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType)
	if e != nil {
		t.Fail()
	}
	if v != 69 {
		t.Fail()
	}
}

func TestGEVIS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(P.XrefData, 0, 1, P.XrefBranchType, 69)
	v, e := m.GetEdgeValueNumbers(P.XrefData, 0, 1)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Type != P.XrefBranchType {
		t.Fail()
	}
	if vv.Value != 69 {
		t.Fail()
	}
}
