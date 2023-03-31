package model

import (
	"bytes"
	"context"
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
	Hostnames       []string
	Isp             *string
	City            *string
	Country         *string
	Organization    *string
	Ports           []int
	Vulnerabilities []string
	IsCdn           *bool
	Cdn             *string
}

type Action struct {
	SrcAddr  *string
	DstAddr  *string
	Hostname *string
	SrcPort  *uint16
	DstPort  *uint16
}

type PortTraffic struct {
	srcPort   *uint16
	dstPort   *uint16
	hostnames []string
}

type ActionsByIp struct {
	ip          *string
	portTraffic *PortTraffic
}

type Model struct {
	logger *logFacility.Logger

	garbageCollectionTicker     *time.Ticker
	garbageCollectionTickerDone chan bool

	tickersDone chan bool

	configuration *ModelConfigurations
	db            *badger.DB

	metaMutex    *sync.RWMutex
	actionsMutex *sync.RWMutex

	metaMerger    map[string]*badger.MergeOperator
	actionsMerger map[string]*badger.MergeOperator
	ipsMerger     *badger.MergeOperator
}

func New(logger *logFacility.Logger, ctx context.Context, modelConfigurations *ModelConfigurations) (*Model, error) {
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

		metaMutex:    &sync.RWMutex{},
		actionsMutex: &sync.RWMutex{},

		metaMerger:    make(map[string]*badger.MergeOperator),
		actionsMerger: make(map[string]*badger.MergeOperator),
	}

	toReturn.ipsMerger = db.GetMergeOperator(ipsKey(), toReturn.mergeIps, modelConfigurations.ModelMergersTime)

	go toReturn.gc()

	return toReturn, nil
}

func (model *Model) Dispose() error {
	model.logger.Log.Debug("Closing data structure")
	model.tickersDone <- true
	model.garbageCollectionTicker.Stop()

	for ip, value := range model.metaMerger {
		model.logger.Log.Debugf("Stopping meta merger for %s", ip)
		value.Stop()
	}

	err := model.db.Close()
	if err != nil {

		return err
	}

	return nil
}

func (model *Model) Get() ([]string, error) {
	var valCopy []byte
	err := model.db.View(func(txn *badger.Txn) error {
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
		return nil, err
	}

	decodedMeta, decodeErr := decode[set](valCopy)
	if decodeErr != nil {

		return nil, decodeErr
	}

	toReturn := make([]string, 0, len(*decodedMeta))
	for k := range *decodedMeta {
		toReturn = append(toReturn, k)
	}

	return toReturn, nil
}

func (model *Model) GetMeta(ip string) (*Meta, error) {
	var valCopy []byte
	err := model.db.View(func(txn *badger.Txn) error {
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
		return nil, err
	}

	decodedMeta, decodeErr := decode[Meta](valCopy)
	if decodeErr != nil {

		return nil, decodeErr
	}

	return decodedMeta, nil
}

func (model *Model) GetActions(ip string) (*ActionsByIp, error) {
	var valCopy []byte
	err := model.db.View(func(txn *badger.Txn) error {
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

func (model *Model) StoreMeta(ip string, meta *Meta) error {
	var mergingOperator *badger.MergeOperator

	model.metaMutex.Lock()
	defer model.metaMutex.Unlock()
	val, ok := model.metaMerger[ip]
	if !ok {
		mergingOperator = model.db.GetMergeOperator(metaKey(ip), model.mergeMeta, 100*time.Millisecond)
		model.metaMerger[ip] = mergingOperator
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

func (model *Model) StoreAction(action *Action) error {
	var scrMergingOperator, dstMergingOperator *badger.MergeOperator

	hostnames := []string{*action.Hostname}[:]

	model.actionsMutex.Lock()
	defer model.actionsMutex.Unlock()
	srcVal, srcMetaKeyIsPresent := model.actionsMerger[*action.SrcAddr]
	if !srcMetaKeyIsPresent {
		scrMergingOperator = model.db.GetMergeOperator(actionKey(*action.SrcAddr), model.mergeActions, 100*time.Millisecond)
		model.metaMerger[*action.SrcAddr] = scrMergingOperator
	} else {
		scrMergingOperator = srcVal
	}

	srcActionsByIp := &ActionsByIp{
		ip: action.SrcAddr,
		portTraffic: &PortTraffic{
			srcPort:   action.SrcPort,
			dstPort:   action.DstPort,
			hostnames: hostnames,
		},
	}

	srcBytes, err := encode(*srcActionsByIp)
	if err != nil {
		return err
	}

	scrMergingOperator.Add(srcBytes)

	dstVal, dstMetaKeyIsPresent := model.actionsMerger[*action.DstAddr]
	if !dstMetaKeyIsPresent {
		dstMergingOperator = model.db.GetMergeOperator(actionKey(*action.DstAddr), model.mergeActions, 100*time.Millisecond)
		model.metaMerger[*action.DstAddr] = dstMergingOperator
	} else {
		dstMergingOperator = dstVal
	}

	dstActionsByIp := &ActionsByIp{
		ip: action.DstAddr,
		portTraffic: &PortTraffic{
			srcPort:   action.DstPort,
			dstPort:   action.SrcPort,
			hostnames: hostnames,
		},
	}

	dstBytes, err := encode(*dstActionsByIp)
	if err != nil {
		return err
	}

	dstMergingOperator.Add(dstBytes)

	return nil
}

type set map[string]interface{}

func (model *Model) gc() {
	model.logger.Log.Debug("Garbage collection local database")
	for {
		select {
		case <-model.tickersDone:
			return
		case <-model.garbageCollectionTicker.C:

			err := model.db.RunValueLogGC(0.7)
			if err != nil && err != badger.ErrNoRewrite {
				model.logger.Log.Errorf("Garbage collection in error: %s", err.Error())
			}
		}
	}
}

func (model *Model) mergeMeta(originalValue, newValue []byte) []byte {
	model.logger.Log.Debugf("Merging meta values")
	originalMeta, originalMetaErr := decode[Meta](originalValue)
	newMeta, newMetaErr := decode[Meta](newValue)
	if originalMetaErr != nil || newMetaErr != nil {
		return originalValue
	}

	newPorts := append(originalMeta.Ports, newMeta.Ports...)
	newHostnames := append(originalMeta.Hostnames, newMeta.Hostnames...)

	originalMeta.Ports = newPorts
	originalMeta.Hostnames = newHostnames

	model.logger.Log.Debugf("Meta values merged, encoding now")
	newBytes, encodingErr := encode(originalMeta)
	if encodingErr != nil {
		return originalValue
	}
	model.logger.Log.Debugf("Meta values encoded")

	return newBytes
}

func (model *Model) mergeActions(originalValue, newValue []byte) []byte {
	model.logger.Log.Debugf("Merging actions values")
	originalDecoded, originalDecodeErr := decode[ActionsByIp](originalValue)
	newDecoded, newDecodeErr := decode[ActionsByIp](newValue)
	if originalDecodeErr != nil || newDecodeErr != nil {
		return originalValue
	}

	newHostnames := append(originalDecoded.portTraffic.hostnames, newDecoded.portTraffic.hostnames...)
	originalDecoded.portTraffic.hostnames = newHostnames

	model.logger.Log.Debugf("Actions values merged, encoding now")
	newBytes, encodingErr := encode(originalDecoded)
	if encodingErr != nil {
		return originalValue
	}
	model.logger.Log.Debugf("Action values encoded")

	return newBytes
}

func (model *Model) mergeIps(originalValue, newValue []byte) []byte {
	model.logger.Log.Debugf("Merging ips")
	originalDecoded, originalDecodeErr := decode[set](originalValue)
	newDecoded, newDecodeErr := decode[set](newValue)
	if originalDecodeErr != nil || newDecodeErr != nil {
		return originalValue
	}

	for k := range *newDecoded {
		(*originalDecoded)[k] = struct{}{}
	}

	model.logger.Log.Debugf("Ips merged, encoding now")
	newBytes, encodingErr := encode(originalDecoded)
	if encodingErr != nil {
		return originalValue
	}
	model.logger.Log.Debugf("Ips values encoded")

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
