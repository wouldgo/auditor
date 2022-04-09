package healthiness

import (
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func dumbHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func Healthiness(logger *zap.SugaredLogger) {
	router := mux.NewRouter()

	router.Path("/live").HandlerFunc(dumbHandler)
	router.Path("/ready").HandlerFunc(dumbHandler)
	logger.Info("Starting healthiness metrics server on port 8080")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		panic(err)
	}
}
