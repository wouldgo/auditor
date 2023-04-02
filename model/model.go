package model

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"

	logFacility "auditor/logger"
)

type ModelConfigurations struct {
	PathWhereStoreDabaseFile *string
	ApplicationName          *string
	ModelMergersTime         time.Duration
}

type Meta struct {
	Hostnames       []string `json:"hostnames,omitempty"`
	Isp             *string  `json:"isp,omitempty"`
	City            *string  `json:"city,omitempty"`
	Country         *string  `json:"country,omitempty"`
	Organization    *string  `json:"organization,omitempty"`
	Ports           []int    `json:"ports,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	IsCdn           *bool    `json:"isCdn,omitempty"`
	Cdn             *string  `json:"cdn,omitempty"`
}

type Action struct {
	SrcAddr  *string
	DstAddr  *string
	Hostname *string
	SrcPort  *uint16
	DstPort  *uint16
}

type ActionsByIp struct {
	Ip      *string
	Traffic map[string][]string
}

type ModelEntity uint8

const (
	Ips ModelEntity = iota
	Actions
)

type NotFoundErr struct {
	Entity ModelEntity
}

var (
	IpNotFoundErr = &NotFoundErr{
		Entity: Ips,
	}
	ActionNotFoundErr = &NotFoundErr{
		Entity: Actions,
	}
)

func (e *NotFoundErr) Error() string {
	return fmt.Sprintf("Entity type %v not found", e.Entity)
}

type Model struct {
	logger *logFacility.Logger

	garbageCollectionTicker     *time.Ticker
	garbageCollectionTickerDone chan bool

	tickersDone chan bool

	configuration *ModelConfigurations
	db            *badger.DB

	metaMutex      *sync.RWMutex
	actionsMutex   *sync.RWMutex
	ipsMergerMutex *sync.RWMutex

	metaMerger    map[string]*badger.MergeOperator
	actionsMerger map[string]*badger.MergeOperator
	ipsMerger     *badger.MergeOperator
}

func New(logger *logFacility.Logger, modelConfigurations *ModelConfigurations) (*Model, error) {
	logger.Log.Debug("Creating data facility")

	databaseLocation := fmt.Sprintf("%s/%s.data", *modelConfigurations.PathWhereStoreDabaseFile, *modelConfigurations.ApplicationName)
	badgerOptions := logger.Level.ToBadger(badger.DefaultOptions(databaseLocation), logger)
	db, err := badger.Open(badgerOptions)
	if err != nil {
		return nil, err
	}

	toReturn := &Model{
		logger: logger,

		garbageCollectionTicker:     time.NewTicker(2 * time.Minute),
		garbageCollectionTickerDone: make(chan bool),

		tickersDone: make(chan bool),

		configuration: modelConfigurations,
		db:            db,

		metaMutex:      &sync.RWMutex{},
		actionsMutex:   &sync.RWMutex{},
		ipsMergerMutex: &sync.RWMutex{},

		metaMerger:    make(map[string]*badger.MergeOperator),
		actionsMerger: make(map[string]*badger.MergeOperator),
	}

	toReturn.ipsMerger = db.GetMergeOperator(ipsKey(), toReturn.mergeIps, modelConfigurations.ModelMergersTime)

	go toReturn.gc()

	return toReturn, nil
}

func (m *Model) Dispose() error {
	m.logger.Log.Debug("Closing data structure")
	m.tickersDone <- true
	m.garbageCollectionTicker.Stop()

	for ip, value := range m.metaMerger {
		m.logger.Log.Debugf("Stopping meta merger for %s", ip)
		value.Stop()
	}

	err := m.db.Close()
	if err != nil {

		return err
	}

	return nil
}

func (m *Model) Get() ([]string, error) {
	var valCopy []byte
	err := m.db.View(func(txn *badger.Txn) error {
		item, innerError := txn.Get(ipsKey())
		if innerError != nil {
			return innerError
		}

		valCopy, innerError = item.ValueCopy(nil)
		if innerError != nil {
			return innerError
		}

		return nil
	})

	if err != nil {
		if err.Error() == errKeyNotFoundStr {

			return []string{}, nil
		}

		return nil, err
	}

	decodedMeta, decodeErr := decode[set](valCopy)
	if decodeErr != nil {

		return nil, decodeErr
	}

	toReturn := make([]string, 0, len(*decodedMeta))
	for k := range *decodedMeta {
		toReturn = append(toReturn, k.(string))
	}

	return toReturn, nil
}

func (m *Model) GetMeta(ip string) (*Meta, error) {
	var valCopy []byte
	err := m.db.View(func(txn *badger.Txn) error {
		item, innerError := txn.Get(metaKey(ip))
		if innerError != nil {
			return innerError
		}

		valCopy, innerError = item.ValueCopy(nil)
		if innerError != nil {
			return innerError
		}

		return nil
	})

	if err != nil {
		if err.Error() == errKeyNotFoundStr {

			return nil, IpNotFoundErr
		}
		return nil, err
	}

	decodedMeta, decodeErr := decode[Meta](valCopy)
	if decodeErr != nil {

		return nil, decodeErr
	}

	return decodedMeta, nil
}

func (m *Model) GetActions(ip string) (*ActionsByIp, error) {
	var valCopy []byte
	err := m.db.View(func(txn *badger.Txn) error {
		item, innerError := txn.Get(actionKey(ip))
		if innerError != nil {
			return innerError
		}

		valCopy, innerError = item.ValueCopy(nil)
		if innerError != nil {
			return innerError
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	decodedActions, decodeErr := decode[ActionsByIp](valCopy)
	if decodeErr != nil {

		return nil, decodeErr
	}

	return decodedActions, nil
}

func (m *Model) StoreMeta(ip string, meta *Meta) error {
	var mergingOperator *badger.MergeOperator

	m.metaMutex.Lock()
	defer m.metaMutex.Unlock()
	val, ok := m.metaMerger[ip]
	if !ok {
		mergingOperator = m.db.GetMergeOperator(metaKey(ip), m.mergeMeta, 100*time.Millisecond)
		m.metaMerger[ip] = mergingOperator
	} else {
		mergingOperator = val
	}

	bytes, err := encode(*meta)
	if err != nil {
		return err
	}
	mergingOperator.Add(bytes)

	return nil
}

func (m *Model) StoreAction(action *Action) error {
	var mergingOperator *badger.MergeOperator

	hostnames := []string{*action.Hostname}

	m.actionsMutex.Lock()
	defer m.actionsMutex.Unlock()
	srcVal, srcMetaKeyIsPresent := m.actionsMerger[*action.SrcAddr]
	if !srcMetaKeyIsPresent {
		mergingOperator = m.db.GetMergeOperator(actionKey(*action.SrcAddr), m.mergeActions, 100*time.Millisecond)
		m.metaMerger[*action.SrcAddr] = mergingOperator
	} else {
		mergingOperator = srcVal
	}

	newTraffic := make(map[string][]string, 1)
	newTraffic[*action.DstAddr] = hostnames

	srcActionsByIp := &ActionsByIp{
		Ip:      action.SrcAddr,
		Traffic: newTraffic,
	}

	srcBytes, err := encode(*srcActionsByIp)
	if err != nil {
		return err
	}

	mergingOperator.Add(srcBytes)

	m.ipsMergerMutex.Lock()
	defer m.ipsMergerMutex.Unlock()

	setToStore := make(set, 1)
	setToStore[*action.SrcAddr] = setElement
	srcIps, errIps := encode(setToStore)
	if errIps != nil {
		return err
	}

	m.ipsMerger.Add(srcIps)

	return nil
}

const errKeyNotFoundStr = "Key not found"

type elementType struct {
	PlaceHolder bool
}

var setElement = elementType{
	PlaceHolder: true,
}

type set map[interface{}]elementType

func (m *Model) gc() {
	m.logger.Log.Debug("Garbage collection local database")
	for {
		select {
		case <-m.tickersDone:
			return
		case <-m.garbageCollectionTicker.C:

			err := m.db.RunValueLogGC(0.7)
			if err != nil && err != badger.ErrNoRewrite {
				m.logger.Log.Errorf("Garbage collection in error: %s", err.Error())
			}
		}
	}
}

func (m *Model) mergeMeta(originalValue, newValue []byte) []byte {
	m.logger.Log.Debugf("Merging meta values")
	originalMeta, originalMetaErr := decode[Meta](originalValue)
	newMeta, newMetaErr := decode[Meta](newValue)
	if originalMetaErr != nil || newMetaErr != nil {
		return originalValue
	}

	newPortsSet := make(set, len(originalMeta.Ports)+len(newMeta.Ports))
	for value := range originalMeta.Ports {
		newPortsSet[value] = setElement
	}

	for value := range newMeta.Ports {
		newPortsSet[value] = setElement
	}

	newPorts := make([]int, 0, len(originalMeta.Ports)+len(newMeta.Ports))
	for k := range newPortsSet {
		newPorts = append(newPorts, k.(int))
	}
	originalMeta.Ports = newPorts

	newHostnamesSet := make(set, len(originalMeta.Ports)+len(newMeta.Ports))
	for _, value := range originalMeta.Hostnames {
		newHostnamesSet[value] = setElement
	}

	for _, value := range newMeta.Hostnames {
		newHostnamesSet[value] = setElement
	}

	newHostnames := make([]string, 0, len(originalMeta.Ports)+len(newMeta.Ports))
	for k := range newHostnamesSet {
		newHostnames = append(newHostnames, k.(string))
	}
	originalMeta.Hostnames = newHostnames

	m.logger.Log.Debugf("Meta values merged, encoding now")
	newBytes, encodingErr := encode(originalMeta)
	if encodingErr != nil {
		return originalValue
	}
	m.logger.Log.Debugf("Meta values encoded")

	return newBytes
}

func (m *Model) mergeActions(originalValue, newValue []byte) []byte {
	m.logger.Log.Debugf("Merging actions values")
	originalDecoded, originalDecodeErr := decode[ActionsByIp](originalValue)
	newDecoded, newDecodeErr := decode[ActionsByIp](newValue)
	if originalDecodeErr != nil || newDecodeErr != nil {
		return originalValue
	}

	for key, value := range newDecoded.Traffic {

		oldTrafficValue, isTrafficPresent := originalDecoded.Traffic[key]
		if isTrafficPresent {
			newHostnamesSet := make(set, len(oldTrafficValue)+len(value))
			for _, value := range oldTrafficValue {
				newHostnamesSet[value] = setElement
			}

			for _, value := range value {
				newHostnamesSet[value] = setElement
			}

			newHostnames := make([]string, 0, len(oldTrafficValue)+len(value))
			for k := range newHostnamesSet {
				newHostnames = append(newHostnames, k.(string))
			}

			originalDecoded.Traffic[key] = newHostnames
		} else {

			originalDecoded.Traffic[key] = value
		}
	}

	m.logger.Log.Debugf("Actions values merged, encoding now")
	newBytes, encodingErr := encode(originalDecoded)
	if encodingErr != nil {
		return originalValue
	}
	m.logger.Log.Debugf("Action values encoded")

	return newBytes
}

func (m *Model) mergeIps(originalValue, newValue []byte) []byte {
	m.logger.Log.Debugf("Merging ips")
	originalDecoded, originalDecodeErr := decode[set](originalValue)
	newDecoded, newDecodeErr := decode[set](newValue)
	if originalDecodeErr != nil || newDecodeErr != nil {
		return originalValue
	}

	for k := range *newDecoded {
		(*originalDecoded)[k] = setElement
	}

	m.logger.Log.Debugf("Ips merged, encoding now")
	newBytes, encodingErr := encode(originalDecoded)
	if encodingErr != nil {
		return originalValue
	}
	m.logger.Log.Debugf("Ips values encoded")

	return newBytes
}

func metaKey(ip string) []byte {
	stringKey := strings.Join([]string{ip, "meta"}, "-")
	return []byte(stringKey)
}

func actionKey(ip string) []byte {
	stringKey := strings.Join([]string{ip, "action"}, "-")
	return []byte(stringKey)
}

func ipsKey() []byte {
	return []byte("ips")
}

func encode[T any](value T) ([]byte, error) {
	var reader bytes.Buffer
	encoder := gob.NewEncoder(&reader)

	err := encoder.Encode(value)
	if err != nil {
		return []byte{}, err
	}

	return reader.Bytes(), nil
}

func decode[T any](b []byte) (*T, error) {
	bufferData := bytes.NewBuffer(b)
	dec := gob.NewDecoder(bufferData)
	var v T
	err := dec.Decode(&v)
	if err != nil {

		return nil, err
	}

	return &v, nil
}
