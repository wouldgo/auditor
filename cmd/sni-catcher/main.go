package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/breml/rootcerts"

	"auditor/api"
	"auditor/healthiness"
	"auditor/meta"
	"auditor/model"
	"auditor/sni"
)

func main() {
	options, err := parseOptions()
	if err != nil {

		panic(err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	model, modelErr := model.New(options.Logger, options.Model)
	if err != nil {
		options.Logger.Log.Fatal(modelErr)
	}

	meta, metaErr := meta.New(options.Logger, model, options.Meta)
	if metaErr != nil {
		options.Logger.Log.Fatal(metaErr)
	}

	sniHandler, sniErr := sni.New(options.Logger, options.Pcap)
	if sniErr != nil {
		options.Logger.Log.Fatal(sniErr)
	}

	api, apiErr := api.New(options.Logger, model)
	if apiErr != nil {
		options.Logger.Log.Fatal(apiErr)
	}

	go sniHandler.Handle()
	go meta.FromChan(sniHandler.C)
	go api.Up()

	go healthiness.Healthiness(options.Logger)
	sig := <-stop
	options.Logger.Log.Infof("Caught %v", sig)

	sniHandler.Close()
	options.Logger.Log.Debug("Sni handler closed")

	meta.Dispose()
	options.Logger.Log.Debug("Meta disposed")
	os.Exit(0)
}
