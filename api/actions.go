package api

import (
	"auditor/model"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type actions struct {
	model *model.Model
}

func registerActionsRoutes(context string, api *Api) {
	toReturn := actions{
		model: api.model,
	}

	actionsRoutes := api.engine.Group(context)
	actionsRoutes.GET("/:ip", toReturn.actionsByIp)
}

func (a *actions) actionsByIp(c *gin.Context) {
	ip := c.Param("ip")
	actions, actionsErr := a.model.GetActions(ip)

	if errors.Is(actionsErr, model.ActionNotFoundErr) {
		c.Status(http.StatusNotFound)
		return
	}

	if actionsErr != nil {
		panic(actionsErr)
	}

	c.JSON(http.StatusOK, actions.Traffic)
}
