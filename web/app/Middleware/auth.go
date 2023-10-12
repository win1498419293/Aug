package Middleware

import (
	"Aug/web/app/service"
	"github.com/gin-gonic/gin"
)

func Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		if service.GetDeployment(c) {

		}
		c.Next()
	}
}
