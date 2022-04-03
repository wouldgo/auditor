package prometheus

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func dumbHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func StartupProm(logger *zap.SugaredLogger) {
	router := mux.NewRouter()

	router.Path("/live").HandlerFunc(dumbHandler)
	router.Path("/ready").HandlerFunc(dumbHandler)
	router.Path("/metrics").Handler(promhttp.Handler())
	logger.Info("Starting prometheus metrics server on port 8080")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("Prometheus metrics server started on 0.0.0.0:8080")
}
