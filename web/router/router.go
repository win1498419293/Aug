package router

import (
	"Aug/web/app/Controllers"
	"github.com/gin-gonic/gin"
)

func InitRouter() *gin.Engine {
	r := gin.Default()

	r.Static("/public", "web/public") // 静态文件服务
	r.LoadHTMLGlob("web/views/**/*")  // 载入html模板目录

	// web路由
	r.GET("/", Controllers.Admingetlogin)
	r.GET("/index", Controllers.Userindex)
	admin := r.Group("/admin")
	{
		admin.POST("/register", Controllers.Admininsert)
		admin.POST("/update", Controllers.Adminupdate)
		admin.POST("/index", Controllers.Adminindex)
		admin.GET("/index", Controllers.Adminindex)
		admin.POST("/login", Controllers.Adminlogin)
		admin.GET("/login", Controllers.Admingetlogin)
		admin.POST("/home", Controllers.Adminhome)
	}
	user := r.Group("/user")

	{
		user.POST("/register", Controllers.Userinsert)
		user.GET("/userinfo", Controllers.Userinfo)
		user.POST("/index", Controllers.Userpostindex)
		user.GET("/menu", Controllers.Usermenu)
	}

	uilt := r.Group("/uilt")

	{
		uilt.GET("/uerinfo", Controllers.Userinfo)

	}

	scan := r.Group("/api/scan")
	{
		scan.GET("/portscan", Controllers.PortScan)
		scan.GET("/ports", Controllers.GetPorts)
		scan.PUT("/ports", Controllers.Putport)
		scan.POST("/manager", Controllers.ManagerputAdd)
		// 添加厂商管理信息
		scan.POST("/managers", Controllers.ApiManagerInfo)
		scan.GET("/engine", Controllers.Engine)
		scan.GET("/manager", Controllers.Manager)
		// 添加资产
		scan.GET("/manager/task", Controllers.ManagerTask)

		//厂商管理信息查询接口
		scan.GET("/managers", Controllers.Managerinfo)
		// 添加厂商信息
		scan.PUT("/manager", Controllers.ManagerputAdd)
		// 添加厂商域名信息
		scan.PUT("/domain", Controllers.AddManufacturerinfo)
		// 查询厂商域名信息
		scan.GET("/domain", Controllers.GetManufacturerinfo)
		// 查询子域名表信息
		scan.GET("/subinfo", Controllers.Getsubinfo)
		// 查询任务表信息
		scan.GET("/taskinfo", Controllers.GetTaskinfo)
		// 查询漏洞表信息
		scan.GET("/vulninfo", Controllers.GetVulninfo)
		// 查询厂商数据信息
		scan.GET("/firminfo", Controllers.Getfirminfo)
		scan.GET("/webinfo", Controllers.Webinfo)

		//web扫描
		scan.PUT("/webinfo", Controllers.PutWebinfo)
		scan.GET("/manager/add", Controllers.ManagerAdd)
		scan.GET("/managerTask", Controllers.ManagerTask)
		//获得子域名数据
		scan.GET("/subdomains", Controllers.GetSubDomain)
		scan.GET("/subdomain", Controllers.SubDomain)
		scan.GET("/webDealis", Controllers.WebDetails)
		scan.GET("/webinfos", Controllers.Webinfos)
		scan.POST("/webinfo/tree", Controllers.Getvulninfo)

	}

	return r
}
