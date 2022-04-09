package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/breml/rootcerts"

	"auditor/healthiness"
	"auditor/meta"
	"auditor/sni"
)

func main() {
	options, err := parseOptions()
	if err != nil {

		panic(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	meta, metaErr := meta.New(options.Log, options.Meta)
	if metaErr != nil {
		options.Log.Fatal(metaErr)
	}

	sniHandler, sniErr := sni.New(options.Log, options.Pcap)
	if sniErr != nil {
		options.Log.Fatal(sniErr)
	}

	go sniHandler.Handle()
	go meta.FromChan(sniHandler.C)
	go healthiness.Healthiness(options.Log)
	sig := <-stop
	options.Log.Infof("Caught %v", sig)

	sniHandler.Close()
	options.Log.Debug("Sni handler closed")

	meta.Dispose()
	options.Log.Debug("Meta disposed")
	os.Exit(0)
}
