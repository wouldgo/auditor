package main

import (
	"auditor/options"
	"auditor/sni"
	"flag"
	"os"
)

var (
	ifaceEnv, ifaceEnvSet = os.LookupEnv("INTERFACE_NAME")
	iface                 = flag.String("iface", "", "Network interface")
)

type Options struct {
	options.OptionsBase
	Pcap *sni.PcapConfiguration
}

func parseOptions() (*Options, error) {
	baseOptions, err := options.Parse()
	if err != nil {
		return nil, err
	}

	if ifaceEnvSet {
		iface = &ifaceEnv
	}

	pcapConf := &sni.PcapConfiguration{
		Interface: iface,
	}

	opts := Options{
		OptionsBase: *baseOptions,
		Pcap:        pcapConf,
	}

	return &opts, nil
}
