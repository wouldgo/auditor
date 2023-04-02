package meta

import (
	logFacility "auditor/logger"
	"auditor/model"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/ns3777k/go-shodan/v4/shodan"
	"github.com/projectdiscovery/cdncheck"
)

type MetaConfiguration struct {
	ShodanApiKey *string

	CacheSize     *int
	CacheEviction *time.Duration

	Dns *string
}

type Meta struct {
	resolver                  *net.Resolver
	log                       *logFacility.Logger
	cache                     *lru.ARCCache
	shodanClient              *shodan.Client
	shodanHostServicesOptions *shodan.HostServicesOptions
	cdncheck                  *cdncheck.Client

	model                *model.Model
	tickersDone          chan bool
	cachePurgeTicker     *time.Ticker
	printCacheInfoTicker *time.Ticker
}

func (meta *Meta) fromIp(ipAddr net.IP) (*model.Meta, error) {
	stringIp := ipAddr.String()
	value, isCached := meta.cache.Get(stringIp)
	if isCached {

		return value.(*model.Meta), nil
	}

	dns, err := meta.resolver.LookupAddr(context.Background(), stringIp)
	if err != nil || len(dns) == 0 {
		meta.log.Log.Warnf("Error looking up %v", stringIp)
	}

	names := make([]string, 0)
	isLocal := false
	for _, dnsEntry := range dns {
		names = append(names, strings.ToLower(dnsEntry[:len(dnsEntry)-1]))

		if strings.HasSuffix(dnsEntry, ".lan.") {
			isLocal = true
		}
	}

	hostnames := names
	if isLocal {
		meta.log.Log.Infof("%v is a local address", hostnames)

		toReturn := &model.Meta{
			Hostnames: hostnames,
		}
		meta.cache.Add(stringIp, toReturn)
		err = meta.model.StoreMeta(stringIp, toReturn)
		if err != nil {
			meta.log.Log.Warn(err)
		}
		return toReturn, nil
	}

	host, err := meta.shodanClient.GetServicesForHost(context.Background(), stringIp, meta.shodanHostServicesOptions)
	if err != nil {
		meta.log.Log.Warnf("Error getting services for %v", stringIp)

		return nil, err
	}

	if len(host.Hostnames) > 0 {

		hostnames = host.Hostnames
	}

	isCdn, cdnOrigin, cdnCheckErr := meta.cdncheck.Check(ipAddr)
	if cdnCheckErr != nil {
		meta.log.Log.Warnf("Error checking cdn for %v", stringIp)

		return nil, err
	}
	isp := strings.ToLower(host.ISP)
	city := strings.ToLower(host.City)
	countryCode := strings.ToLower(host.CountryCode)
	organization := strings.ToLower(host.Organization)
	ports := host.Ports
	vulnerabilities := host.Vulnerabilities

	toReturn := &model.Meta{
		Hostnames:       hostnames,
		Isp:             &isp,
		City:            &city,
		Country:         &countryCode,
		Organization:    &organization,
		Ports:           ports,
		Vulnerabilities: vulnerabilities,
		IsCdn:           &isCdn,
		Cdn:             &cdnOrigin,
	}

	meta.cache.Add(stringIp, toReturn)
	err = meta.model.StoreMeta(stringIp, toReturn)
	if err != nil {
		meta.log.Log.Warn(err)
	}
	return toReturn, nil
}

func (meta *Meta) fromString(ipAddr string) (*model.Meta, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, errors.New("Address " + ipAddr + " is not valid")
	}

	thisMeta, err := meta.fromIp(ip)
	if err != nil {
		return nil, err
	}
	return thisMeta, nil
}

func (meta *Meta) FromChan(metaChan chan *model.Action) {
	var wg sync.WaitGroup
	for aMetaInput := range metaChan {

		wg.Add(1)
		go toModel(meta, aMetaInput, &wg)
	}
	wg.Wait()
}

func toModel(meta *Meta, aMetaInput *model.Action, wg *sync.WaitGroup) {
	defer wg.Done()

	if _, srcAddrErr := meta.fromString(*aMetaInput.SrcAddr); srcAddrErr != nil {

		meta.log.Log.Warn(srcAddrErr)
	}

	if _, dstsrcAddrErr := meta.fromString(*aMetaInput.DstAddr); dstsrcAddrErr != nil {

		meta.log.Log.Warn(dstsrcAddrErr)
	}

	if err := meta.model.StoreAction(aMetaInput); err != nil {

		meta.log.Log.Warn(err)
	}
}

func (meta *Meta) Dispose() {
	meta.tickersDone <- true
	meta.model.Dispose()
	meta.cachePurgeTicker.Stop()
	meta.printCacheInfoTicker.Stop()
}

func New(logger *logFacility.Logger, model *model.Model, metaConfs *MetaConfiguration) (*Meta, error) {
	cache, cacheCreateErr := lru.NewARC(*metaConfs.CacheSize)
	if cacheCreateErr != nil {

		return nil, cacheCreateErr
	}

	client, err := cdncheck.NewWithCache()

	if err != nil {
		return nil, err
	}

	toReturn := &Meta{
		log:          logger,
		cache:        cache,
		shodanClient: shodan.NewClient(nil, *metaConfs.ShodanApiKey),
		model:        model,
		shodanHostServicesOptions: &shodan.HostServicesOptions{
			History: false,
			Minify:  true,
		},
		cdncheck: client,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * time.Duration(10),
				}
				return d.DialContext(ctx, network, *metaConfs.Dns)
			},
		},
		tickersDone:          make(chan bool),
		cachePurgeTicker:     time.NewTicker(*metaConfs.CacheEviction),
		printCacheInfoTicker: time.NewTicker(time.Hour / 2),
	}

	go toReturn.cachePurge()
	go toReturn.printCacheInfo()

	return toReturn, nil
}

func (m *Meta) cachePurge() {
	for {
		select {
		case <-m.tickersDone:
			return
		case <-m.cachePurgeTicker.C:
			m.log.Log.Debugf("Cache evictor started")
			m.cache.Purge()
			m.log.Log.Debugf("Cache is purged")
		}
	}
}

func (m *Meta) printCacheInfo() {
	for {
		select {
		case <-m.tickersDone:
			return
		case <-m.printCacheInfoTicker.C:
			cachedEntries := m.cache.Len()
			m.log.Log.Debugf("Cached entries are %v", cachedEntries)
		}
	}
}
