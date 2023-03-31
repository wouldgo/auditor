package main

import (
	"auditor/options"
	"auditor/sni"
	"flag"
	"os"
)

var (
	ifaceEnv, ifaceEnvSet = os.LookupEnv("INTERFACE_NAME")
	iface                 = flag.String("iface", "enp0s31f6", "Network interface. Defaults enp0s31f6 ...")

	bpfFilterEnv, bpfFilterEnvSet = os.LookupEnv("BPF_FILTER")
	bpfFilter                     = flag.String("bpf-filter", "(dst port 443)", "BPF filter. Defaults to traffic with destination port 443")
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

	if bpfFilterEnvSet {
		bpfFilter = &bpfFilterEnv
	}

	pcapConf := &sni.PcapConfiguration{
		Interface: iface,
		Filter:    bpfFilter,
	}

	opts := Options{
		OptionsBase: *baseOptions,
		Pcap:        pcapConf,
	}

	return &opts, nil
}
