package mem_persistence

import (
	A "github.com/williballenthin/Lancelot/artifacts"
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
	e := m.SetAddressValueString(A.FunctionData, 0, A.FunctionName, "sub_401000")
	if e != nil {
		t.Fail()
	}
	if m.addressDataS[A.FunctionData][0][A.FunctionName] != "sub_401000" {
		t.Fail()
	}
}

func TestDAVS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(A.FunctionData, 0, A.FunctionName, "sub_401000")
	e := m.DelAddressValueString(A.FunctionData, 0, A.FunctionName)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.addressDataS[A.FunctionData][0][A.FunctionName]; ok {
		t.Fail()
	}
}

func TestGAVS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(A.FunctionData, 0, A.FunctionName, "sub_401000")
	v, e := m.GetAddressValueString(A.FunctionData, 0, A.FunctionName)
	if e != nil {
		t.Fail()
	}
	if v != "sub_401000" {
		t.Fail()
	}
}

func TestGAVSS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueString(A.FunctionData, 0, A.FunctionName, "sub_401000")
	v, e := m.GetAddressValueStrings(A.FunctionData, 0)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Key != A.FunctionName {
		t.Fail()
	}
	if vv.Value != "sub_401000" {
		t.Fail()
	}
}

func TestSAVI(t *testing.T) {
	m, _ := New()
	e := m.SetAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta, 69)
	if e != nil {
		t.Fail()
	}
	if m.addressDataI[A.FunctionData][0][A.FunctionStackDelta] != 69 {
		t.Fail()
	}
}

func TestDAVI(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta, 69)
	e := m.DelAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.addressDataI[A.FunctionData][0][A.FunctionStackDelta]; ok {
		t.Fail()
	}
}

func TestGAVI(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta, 69)
	v, e := m.GetAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta)
	if e != nil {
		t.Fail()
	}
	if v != 69 {
		t.Fail()
	}
}

func TestGAVIS(t *testing.T) {
	m, _ := New()
	m.SetAddressValueNumber(A.FunctionData, 0, A.FunctionStackDelta, 69)
	v, e := m.GetAddressValueNumbers(A.FunctionData, 0)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Key != A.FunctionStackDelta {
		t.Fail()
	}
	if vv.Value != 69 {
		t.Fail()
	}
}

func TestSEVS(t *testing.T) {
	m, _ := New()
	e := m.SetEdgeValueString(A.XrefData, 0, 1, A.XrefName, "sub_401000")
	if e != nil {
		t.Fail()
	}
	if m.edgeDataS[A.XrefData][0][1][A.XrefName] != "sub_401000" {
		t.Fail()
	}
}

func TestDEVS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(A.XrefData, 0, 1, A.XrefName, "sub_401000")
	e := m.DelEdgeValueString(A.XrefData, 0, 1, A.XrefName)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.edgeDataS[A.XrefData][0][1][A.XrefName]; ok {
		t.Fail()
	}
}

func TestGEVS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(A.XrefData, 0, 1, A.XrefName, "sub_401000")
	v, e := m.GetEdgeValueString(A.XrefData, 0, 1, A.XrefName)
	if e != nil {
		t.Fail()
	}
	if v != "sub_401000" {
		t.Fail()
	}
}

func TestGEVSS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueString(A.XrefData, 0, 1, A.XrefName, "sub_401000")
	v, e := m.GetEdgeValueStrings(A.XrefData, 0, 1)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Key != A.XrefName {
		t.Fail()
	}
	if vv.Value != "sub_401000" {
		t.Fail()
	}
}

func TestSEVI(t *testing.T) {
	m, _ := New()
	e := m.SetEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType, 69)
	if e != nil {
		t.Fail()
	}
	if m.edgeDataI[A.XrefData][0][1][A.XrefBranchType] != 69 {
		t.Fail()
	}
}

func TestDEVI(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType, 69)
	e := m.DelEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType)
	if e != nil {
		t.Fail()
	}
	if _, ok := m.edgeDataI[A.XrefData][0][1][A.XrefBranchType]; ok {
		t.Fail()
	}
}

func TestGEVI(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType, 69)
	v, e := m.GetEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType)
	if e != nil {
		t.Fail()
	}
	if v != 69 {
		t.Fail()
	}
}

func TestGEVIS(t *testing.T) {
	m, _ := New()
	m.SetEdgeValueNumber(A.XrefData, 0, 1, A.XrefBranchType, 69)
	v, e := m.GetEdgeValueNumbers(A.XrefData, 0, 1)
	if e != nil {
		t.Fail()
	}
	if len(v) != 1 {
		t.Fail()
	}
	vv := v[0]

	if vv.Key != A.XrefBranchType {
		t.Fail()
	}
	if vv.Value != 69 {
		t.Fail()
	}
}
