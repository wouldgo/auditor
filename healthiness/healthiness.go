package healthiness

import (
	"net/http"

	logFacility "auditor/logger"
)

func dumbHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func Healthiness(logger *logFacility.Logger) {
	router := http.NewServeMux()

	router.HandleFunc("/live", dumbHandler)
	router.HandleFunc("/ready", dumbHandler)
	logger.Log.Info("Starting healthiness metrics server on port 8080")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		panic(err)
	}
}
