package meta

import (
	"auditor/model"
	"context"
	"errors"
	"net"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"

	"github.com/ns3777k/go-shodan/v4/shodan"
)

type MetaConfiguration struct {
	PostgresqlConfigurations *model.PostgresqlConfigurations

	ShodanApiKey *string

	CacheSize     *int
	CacheEviction *time.Duration

	Dns *string
}

type Meta struct {
	resolver                  *net.Resolver
	log                       *zap.SugaredLogger
	cache                     *lru.ARCCache
	locale                    *string
	shodanClient              *shodan.Client
	shodanHostServicesOptions *shodan.HostServicesOptions
	model                     *model.Model
	tickersDone               chan bool
	cachePurgeTicker          *time.Ticker
	printCacheInfoTicker      *time.Ticker
}

func (meta *Meta) fromIp(ipAddr net.IP) (*model.MetaResult, error) {
	stringIp := ipAddr.String()
	value, isCached := meta.cache.Get(stringIp)
	if isCached {

		return value.(*model.MetaResult), nil
	}

	dns, err := meta.resolver.LookupAddr(context.Background(), stringIp)
	if err != nil || len(dns) == 0 {
		meta.log.Warnf("Error looking up %v", stringIp)
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
		meta.log.Infof("%v is a local address", hostnames)

		toReturn := &model.MetaResult{
			Hostnames: hostnames,
		}
		meta.cache.Add(stringIp, toReturn)
		err = meta.model.Store(context.Background(), stringIp, toReturn)
		if err != nil {
			meta.log.Warn(err)
		}
		return toReturn, nil
	}

	exists, err := meta.model.Exists(context.Background(), stringIp)
	if err != nil {
		return nil, err
	}

	if exists { //XXX QUI METTICI IL CERVELLO
		meta.log.Debugf("%v is already in the database", stringIp)

		return nil, nil
	}

	host, err := meta.shodanClient.GetServicesForHost(context.Background(), stringIp, meta.shodanHostServicesOptions)
	if err != nil {
		meta.log.Warnf("Error getting services for %v", stringIp)

		return nil, err
	}

	if len(host.Hostnames) > 0 {

		hostnames = host.Hostnames
	}

	isp := strings.ToLower(host.ISP)
	city := strings.ToLower(host.City)
	countryCode := strings.ToLower(host.CountryCode)
	organization := strings.ToLower(host.Organization)
	ports := host.Ports
	vulnerabilities := host.Vulnerabilities

	toReturn := &model.MetaResult{
		Hostnames:       hostnames,
		Isp:             &isp,
		City:            &city,
		Country:         &countryCode,
		Organization:    &organization,
		Ports:           &ports,
		Vulnerabilities: &vulnerabilities,
	}

	meta.cache.Add(stringIp, toReturn)
	err = meta.model.Store(context.Background(), stringIp, toReturn)
	if err != nil {
		meta.log.Warn(err)
	}
	return toReturn, nil
}

func (meta *Meta) fromString(ipAddr string) (*model.MetaResult, error) {
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

func (meta *Meta) FromChan(ipChan chan string) {
	for ip := range ipChan {
		result, err := meta.fromString(ip)
		if err != nil {

			meta.log.Warn(err)
		}

		if result != nil {

			meta.log.Debugf("%v meta for %s", result.Hostnames, ip)
		}
	}
}

func (meta *Meta) Dispose() {
	meta.tickersDone <- true
	meta.model.Dispose()
	meta.cachePurgeTicker.Stop()
	meta.printCacheInfoTicker.Stop()
}

func New(logger *zap.SugaredLogger, metaConfs *MetaConfiguration) (*Meta, error) {
	model, err := model.New(logger, context.Background(), metaConfs.PostgresqlConfigurations)
	if err != nil {
		return nil, err
	}

	cache, cacheCreateErr := lru.NewARC(*metaConfs.CacheSize)
	if cacheCreateErr != nil {

		return nil, cacheCreateErr
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
		case _ = <-m.cachePurgeTicker.C:
			m.log.Debugf("Cache evictor started")
			m.cache.Purge()
			m.log.Debugf("Cache is purged")
		}
	}
}

func (m *Meta) printCacheInfo() {
	for {
		select {
		case <-m.tickersDone:
			return
		case _ = <-m.printCacheInfoTicker.C:
			cachedEntries := m.cache.Len()
			m.log.Debugf("Cached entries are %v", cachedEntries)
		}
	}
}
