package main

import (
	"auditor/handling"
	"auditor/options"
	"flag"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	networkCidrEnv, networkCidrEnvSet = os.LookupEnv("NETWORK_CIDR")
	networkCidr                       = flag.String("network-cidr", "192.168.1.1/24", "Network CIDR to consider")

	ipExclusionEnv, ipExclusionEnvSet = os.LookupEnv("IP_EXCLUSION")
	ipExclusion                       = flag.String("ip-exclusion", "", "Comma separated ips to exclude from the network")

	listenAddrEnv, listenAddrEnvSet = os.LookupEnv("NFLOW_LISTEN_ADDR")
	listenAddr                      = flag.String("listen-addr", "netflow://:2055", "Address and port to listen on")

	formatEnv, formatEnvSet = os.LookupEnv("NFLOW_FORMAT")
	format                  = flag.String("format", "format", "Formatter to use: take a look at https://github.com/netsampler/goflow2/tree/main/format")

	transportEnv, transportEnvSet = os.LookupEnv("NFLOW_TRANSPORT")
	transport                     = flag.String("transport", "to-channel", "Transport to use: take a look at https://github.com/netsampler/goflow2/tree/main/transport")

	workersEnv, workersEnvSet = os.LookupEnv("NFLOW_WORKERS")
	workers                   = flag.Int("workers", 1, "Number of nflow ingestion workers")
)

type Options struct {
	options.OptionsBase
	Nflow *handling.NflowConfiguration
}

func parseOptions() (*Options, error) {
	baseOptions, err := options.Parse()
	if err != nil {
		return nil, err
	}

	if networkCidrEnvSet {
		networkCidr = &networkCidrEnv
	}

	_, cidrToConsider, err := net.ParseCIDR(*networkCidr)
	if err != nil {

		return nil, err
	}

	if ipExclusionEnvSet {

		ipExclusion = &ipExclusionEnv
	}

	var ipsToExclude []*net.IP
	for _, ip := range strings.Split(*ipExclusion, ",") {

		ipParsed := net.ParseIP(ip)
		ipsToExclude = append(ipsToExclude, &ipParsed)
	}

	if listenAddrEnvSet {

		listenAddr = &listenAddrEnv
	}

	listenAddrUrl, err := url.Parse(*listenAddr)
	if err != nil {
		return nil, err
	}

	hostname := listenAddrUrl.Hostname()
	port, err := strconv.ParseUint(listenAddrUrl.Port(), 10, 64)
	if err != nil {

		return nil, err
	}

	if formatEnvSet {
		format = &formatEnv
	}

	if transportEnvSet {
		transport = &transportEnv
	}

	if workersEnvSet {
		workersFromEnv, err := strconv.ParseInt(workersEnv, 10, 32)
		if err != nil {
			return nil, err
		}

		*workers = int(workersFromEnv)
	}

	nFlowConf := &handling.NflowConfiguration{
		Format:    format,
		Transport: transport,

		Workers:    workers,
		Hostname:   &hostname,
		Port:       &port,
		Cidr:       cidrToConsider,
		Exclusions: ipsToExclude,
	}

	opts := Options{
		OptionsBase: *baseOptions,
		Nflow:       nFlowConf,
	}

	return &opts, nil
}
