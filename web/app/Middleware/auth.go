package Middleware

import (
	"Aug/web/app/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !service.GetDeployment(c) {

			c.Abort()
			// 认证失败，重定向到登录页面
			c.Redirect(http.StatusFound, "/")

			return
		}
		c.Next()
	}
}
