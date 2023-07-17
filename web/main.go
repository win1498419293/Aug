package web

import (
	_ "Aug/web/config"
	_ "Aug/web/database"
	"Aug/web/router"
	"os"
)

func Webmain() {
	r := router.InitRouter()
	port := os.Getenv("HTTP_PORT")
	r.Run(":" + port) // 监听并在 0.0.0.0:8080 上启动服务
}
