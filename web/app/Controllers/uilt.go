package Controllers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func Uiltportmanger(c *gin.Context) {
	c.HTML(http.StatusOK, "PortScanManager.html", gin.H{
		"title": "这是首页",
	})

}
