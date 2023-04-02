package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/breml/rootcerts"

	"auditor/api"
	"auditor/handling"
	"auditor/healthiness"
	"auditor/meta"
	"auditor/model"
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

	intoCtx := map[string]interface{}{
		"logger":    options.Logger,
		"nflowConf": options.Nflow,
	}

	ctx := context.WithValue(context.Background(), handling.CxtKey, intoCtx)
	defer ctx.Done()
	handler, err := handling.New(ctx, options.Logger, options.Nflow)
	if err != nil {
		panic(err)
	}

	api, apiErr := api.New(options.Logger, model)
	if apiErr != nil {
		options.Logger.Log.Fatal(apiErr)
	}

	go handler.Handle()
	go meta.FromChan(handler.Actions)
	go api.Up()

	go healthiness.Healthiness(options.Logger)
	sig := <-stop
	options.Logger.Log.Infof("Caught %v", sig)

	handler.Close(ctx)
	options.Logger.Log.Debug("Nflow handler closed")

	meta.Dispose()
	options.Logger.Log.Debug("Meta disposed")
	os.Exit(0)
}
