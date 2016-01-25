package log_persistence

import (
	"github.com/Sirupsen/logrus"
	AS "github.com/williballenthin/Lancelot/address_space"
	P "github.com/williballenthin/Lancelot/persistence"
)

type LogPersistence struct{}

// New constructs a new LogPersistence instance
func New() (*LogPersistence, error) {
	return &LogPersistence{}, nil
}

/** LogPersistence implements interface Persistence **/

func (m *LogPersistence) SetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS, value string) error {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
		"value": value,
	}).Info("SetAddressValueString")
	return nil
}

func (m *LogPersistence) DelAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) error {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
	}).Info("DelAddressValueString")
	return nil
}

func (m *LogPersistence) GetAddressValueString(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyS) (string, error) {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
	}).Info("GetAddressValueString")
	return "", P.ErrNotImplemented
}

func (m *LogPersistence) GetAddressValueStrings(atype P.AddressDataType, va AS.VA) ([]P.AddressValueString, error) {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
	}).Info("GetAddressValueStrings")
	var ret []P.AddressValueString
	return ret, P.ErrNotImplemented
}

func (m *LogPersistence) SetAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI, value int64) error {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
		"value": value,
	}).Info("SetAddressValueNumber")
	return nil
}

func (m *LogPersistence) DelAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) error {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
	}).Info("DelAddressValueNumber")
	return nil
}

func (m *LogPersistence) GetAddressValueNumber(atype P.AddressDataType, va AS.VA, key P.AddressDataKeyI) (int64, error) {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
		"key":   key,
	}).Info("GetAddressValueNumber")
	return 0, P.ErrNotImplemented
}

func (m *LogPersistence) GetAddressValueNumbers(atype P.AddressDataType, va AS.VA) ([]P.AddressValueNumber, error) {
	logrus.WithFields(logrus.Fields{
		"atype": atype,
		"va":    va,
	}).Info("GetAddressValueNumber")
	var ret []P.AddressValueNumber
	return ret, P.ErrNotImplemented
}

func (m *LogPersistence) SetEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS, value string) error {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
		"value": value,
	}).Info("SetEdgeValueString")
	return nil
}

func (m *LogPersistence) DelEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) error {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
	}).Info("DelEdgeValueString")
	return nil
}

func (m *LogPersistence) GetEdgeValueString(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyS) (string, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
	}).Info("GetEdgeValueString")
	return "", P.ErrNotImplemented
}

func (m *LogPersistence) GetEdgeValueStrings(etype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueString, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
	}).Info("GetEdgeValueStrings")
	var ret []P.EdgeValueString
	return ret, P.ErrNotImplemented
}

func (m *LogPersistence) SetEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI, value int64) error {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
		"value": value,
	}).Info("SetEdgeValueNumber")
	return nil
}

func (m *LogPersistence) DelEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) error {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
	}).Info("DetEdgeValueNumber")
	return nil
}

func (m *LogPersistence) GetEdgeValueNumber(etype P.EdgeDataType, from AS.VA, to AS.VA, key P.EdgeDataKeyI) (int64, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
		"key":   key,
	}).Info("GetEdgeValueNumber")
	return 0, P.ErrNotImplemented
}

func (m *LogPersistence) GetEdgeValueNumbers(etype P.EdgeDataType, from AS.VA, to AS.VA) ([]P.EdgeValueNumber, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
		"to":    to,
	}).Info("GetEdgeValueNumbers")
	var ret []P.EdgeValueNumber
	return ret, P.ErrNotImplemented
}

func (m *LogPersistence) GetEdgesFrom(etype P.EdgeDataType, from AS.VA) ([]AS.VA, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"from":  from,
	}).Info("GetEdgesFrom")
	var ret []AS.VA
	return ret, P.ErrNotImplemented
}

func (m *LogPersistence) GetEdgesTo(etype P.EdgeDataType, to AS.VA) ([]AS.VA, error) {
	logrus.WithFields(logrus.Fields{
		"etype": etype,
		"to":    to,
	}).Info("GetEdgesTo")
	var ret []AS.VA
	return ret, P.ErrNotImplemented
}
