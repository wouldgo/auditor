package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/breml/rootcerts"

	"auditor/handling"
	"auditor/meta"
	prometheusMetrics "auditor/prometheus"
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

	intoCtx := map[string]interface{}{
		"logger":    options.Log,
		"nflowConf": options.Nflow,
	}
	ctx := context.WithValue(context.Background(), handling.CxtKey, intoCtx)
	defer ctx.Done()
	handler, err := handling.New(ctx, options.Log, options.Nflow)
	if err != nil {
		panic(err)
	}

	go prometheusMetrics.StartupProm(options.Log)
	go handler.Handle()
	go meta.FromChan(handler.Ips)
	sig := <-stop
	options.Log.Infof("Caught %v", sig)

	handler.Close(ctx)
	options.Log.Debug("Nflow handler closed")

	meta.Dispose()
	options.Log.Debug("Meta disposed")
	os.Exit(0)
}
