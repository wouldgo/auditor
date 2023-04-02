package api

import (
	"auditor/model"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ips struct {
	model *model.Model
}

func registerIpsRoutes(context string, api *Api) {
	toReturn := ips{
		model: api.model,
	}

	ipRoutes := api.engine.Group(context)
	ipRoutes.GET("/", toReturn.allIps)
	ipRoutes.GET("/:ip", toReturn.metaByIp)
}

func (i *ips) allIps(c *gin.Context) {
	ips, ipsErr := i.model.Get()
	if ipsErr != nil {
		panic(ipsErr)
	}

	c.JSON(http.StatusOK, ips)
}

func (i *ips) metaByIp(c *gin.Context) {
	ip := c.Param("ip")
	meta, metaErr := i.model.GetMeta(ip)

	if errors.Is(metaErr, model.IpNotFoundErr) {
		c.Status(http.StatusNotFound)
		return
	}

	if metaErr != nil {

		panic(metaErr)
	}

	c.JSON(http.StatusOK, meta)
}
