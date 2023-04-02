package api

import (
	logFacility "auditor/logger"
	"auditor/model"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
)

type Api struct {
	engine *gin.Engine
	model  *model.Model
}

func New(logger *logFacility.Logger, model *model.Model) (*Api, error) {
	desugaredZap := logger.Log.Desugar()

	engine := gin.New()
	//https://github.com/gin-gonic/gin/blob/master/docs/doc.md#dont-trust-all-proxies
	engine.SetTrustedProxies(nil)

	ginzapLogger := ginzap.Ginzap(desugaredZap, time.RFC3339, true)
	ginzapRecovery := ginzap.RecoveryWithZap(desugaredZap, true)

	engine.Use(ginzapLogger, ginzapRecovery)

	toReturn := &Api{
		engine: engine,
		model:  model,
	}

	registerIpsRoutes("/ip", toReturn)
	registerActionsRoutes("/actions", toReturn)

	return toReturn, nil
}

func (a *Api) Up() {
	a.engine.Run(":3000")
}
