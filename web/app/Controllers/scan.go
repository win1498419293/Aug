package Controllers

import (
	"Aug/lib"
	"Aug/web/app/Models"
	"Aug/web/app/service"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strconv"
)

func PortScan(c *gin.Context) {
	c.HTML(http.StatusOK, "Ports.html", gin.H{
		"title": "这是首页",
	})
}

func Engine(c *gin.Context) {
	c.HTML(http.StatusOK, "Engine.html", gin.H{
		"title": "这是首页",
	})
}

func Manager(c *gin.Context) {

	c.HTML(http.StatusOK, "Manager.html", gin.H{
		"title": "这是首页",
	})
}

func ManagerAdd(c *gin.Context) {
	c.HTML(http.StatusOK, "ManagerAdd.html", gin.H{
		"title": "这是首页",
	})
}

// 添加厂商信息
func ManagerputAdd(c *gin.Context) {
	var json Models.Cusinfo    //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据
	err = json.ManageInsert()
	if err != nil {
		loginmsg := Models.Scanmsg{
			Status:  false,
			Message: "添加失败",
			Error:   err,
		}
		c.JSON(http.StatusOK, loginmsg)
		return
	}
	loginmsg := Models.Loginmsg{
		Code:    200,
		Status:  true,
		Message: "添加成功",
	}
	c.JSON(http.StatusOK, loginmsg)
	lib.AllScan("", json.Domain, json.CusName, 1)
}

// 添加厂商信息
func AddManufacturerinfo(c *gin.Context) {
	var json Models.Manufacturerinfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)       //  获取前台传过来的 json数据
	err = json.ManufacturerinfoInsert()

	if err != nil {
		loginmsg := Models.Scanmsg{
			Status:  false,
			Message: "添加失败",
			Error:   err,
		}
		c.JSON(http.StatusOK, loginmsg)
		return
	}
	loginmsg := Models.Loginmsg{
		Status:  true,
		Message: "添加成功",
	}
	c.JSON(http.StatusOK, loginmsg)
}

// 添加厂商管理信息
func ApiManagerInfo(c *gin.Context) {
	var json Models.ResAPiScanManagerInfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.BindJSON(&json)              //  获取前台传过来的 json数据
	fmt.Printf(string(json.CusSudDomainNum))
	id, err := json.ApiManagerInfo()
	if err != nil {
		loginmsg := Models.Scanmsg{
			Status:  false,
			Message: "添加失败",
			Error:   err,
		}
		c.JSON(http.StatusOK, loginmsg)
		return
	}
	loginmsg := Models.Loginmsg{
		Status:  true,
		Id:      id,
		Code:    200,
		Message: "添加成功",
	}
	c.JSON(http.StatusOK, loginmsg)
}

func ManagerTask(c *gin.Context) {
	c.HTML(http.StatusOK, "ManagerTask.html", gin.H{
		"title": "这是首页",
	})
}

func Webinfo(c *gin.Context) {

	c.HTML(http.StatusOK, "WebInfo.html", gin.H{
		"data": "da",
	})
}

func Webinfos(c *gin.Context) {
	var json service.Webinfo   //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	res, err := json.Getwebinfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.ResWebinfo{
		Code: 0,
		Msg:  "ok",
		Data: res,
	}
	c.JSON(http.StatusOK, AScanManage)
}

// web扫描
func PutWebinfo(c *gin.Context) {
	var json Models.WebScaninfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)  //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := Models.Scanmsg{
		Code:    200,
		Message: "ok",
	}
	c.JSON(http.StatusOK, AScanManage)
	thread := os.Getenv("THREAD")
	json.Thread, err = strconv.Atoi(thread)

	if err != nil {
		// 处理转换错误
		fmt.Println("thread转换失败:", err)
		return
	}

	flag := os.Getenv("Web_Scan_Flag")
	json.Flag, err = strconv.ParseBool(flag)
	if err != nil {
		// 处理转换错误
		fmt.Println("flag转换失败:", err)
		return
	}
	/*
		JsSensitiveData := lib.Finderjs(json.Url)
		lib.Katanascan(json.Url)
		for i := 0; i < len(JsSensitiveData); i++ {
			xrayresult := lib.StartCrawlerGo(JsSensitiveData[i], json.Thread)
			resultfile, err := os.Stat(xrayresult)
			if xrayresult != "" && err == nil && resultfile.Size() > 0 {
				ghr := lib.GetXrayHtmlResult(xrayresult)
				for _, vaule := range ghr {
					if vaule["addr"] != "" {
						fmt.Println(vaule["createTi"], vaule["target"], vaule["plugin"])
					}
				}
			}
		}

	*/
	color.Magenta("开始目录扫描")
	//	lib.Dirsearchscan(json.Url, json.Thread)
	color.Magenta("目录扫描结束")
	color.Cyan("开始指纹识别")
	lib.FingerScan(json.Url)
	color.Cyan("指纹识别结束")
	color.Yellow("开始vulmap扫描")
	lib.Vulmapscan(json.Url, json.Src, json.Thread, json.Flag)
	color.Yellow("vulmap扫描结束")
	color.Red("开始nuclei扫描")
	lib.Nucleiscan(json.Url, json.Src, json.Flag)
	color.Red("nuclei扫描结束")
	color.White("开始pocbomber扫描")
	lib.Pocbomberscan(json.Url, json.Src, json.Thread, json.Flag)
	color.White("pocbomber扫描结束")
	color.Green("开始Find-SomeThing扫描")
	lib.FindSomeThingscan(json.Url, json.Src, json.Flag)
	color.Green("Find-SomeThing扫描结束")

}

func SubDomain(c *gin.Context) {
	c.HTML(http.StatusOK, "SubDomain.html", gin.H{
		"title": "这是首页",
	})
}

func GetSubDomain(c *gin.Context) {
	var json service.Subdomain //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetSubinfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.Subdomaininfo{
		Code: 0,
		Msg:  "ok",
		Data: res,
	}

	c.JSON(http.StatusOK, AScanManage)
}

func GetPorts(c *gin.Context) {
	var json service.ResPortInfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)   //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetPorts()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.Portinfo{
		Code: 0,
		Msg:  "ok",
		Data: res,
	}

	c.JSON(http.StatusOK, AScanManage)
}

func Putport(c *gin.Context) {
	var json Models.PotrScaninfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)
	if err != nil {
		fmt.Printf("ShouldBind %v", err)
	}
	AScanManage := Models.Scanmsg{
		Code:    200,
		Message: "ok",
	}
	c.JSON(http.StatusOK, AScanManage)
	lib.IpScan(false, json.Ip, json.Ports, "", "")
}

func WebDetails(c *gin.Context) {
	c.HTML(http.StatusOK, "WebDetails.html", gin.H{
		"title": "这是首页",
	})
}

func ManagerPostAdd(c *gin.Context) {
	var json service.ResAPiScanManagerInfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)             //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	id, err := json.Scandmoain()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.ResAPiScanManager{
		Code:  200,
		Msg:   "查询成功",
		Count: 1,
		Data:  id,
	}
	c.JSON(http.StatusOK, AScanManage)

}

// 厂商管理信息查询接口
func Managerinfo(c *gin.Context) {
	var json service.ResAPiScanManagerInfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)             //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	id, err := json.Managers()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.ResAPiScanManager{
		Code:  0,
		Msg:   "查询成功",
		Count: 1,
		Data:  id,
	}
	c.JSON(http.StatusOK, AScanManage)

}

// 厂商管理信息查询接口
func GetManufacturerinfo(c *gin.Context) {
	var json service.Manufacturerinfo //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json)        //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetManufacturerinfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	AScanManage := service.Srcinfo{
		Code: 0,
		Msg:  "ok",
		Data: res,
	}
	c.JSON(http.StatusOK, AScanManage)

}

// 子域名查询接口
func Getsubinfo(c *gin.Context) {
	var json service.Subdomain //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetSubinfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}

	c.JSON(http.StatusOK, res)

}

// 任务表查询接口
func GetTaskinfo(c *gin.Context) {
	var json service.Task      //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetTaskinfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}

	c.JSON(http.StatusOK, res)

}

// 漏洞表查询接口
func GetVulninfo(c *gin.Context) {
	var json service.Vuln      //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetVulninfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}

	c.JSON(http.StatusOK, res)

}

// 查询厂商数据信息
func Getfirminfo(c *gin.Context) {
	var json service.Firminfo  //  定义json 变量 数据结构类型 为 Models.Admins
	err := c.ShouldBind(&json) //  获取前台传过来的 json数据

	if err != nil {
		fmt.Printf("mysql connect error %v", err)
	}
	res, err := json.GetFirminfo()

	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}

	c.JSON(http.StatusOK, res)

}

func Getvulninfo(c *gin.Context) {
	var json service.WebTreeInfo
	err := c.ShouldBind(&json)
	res, err := json.Getvulninfo(json.Url)
	if err != nil {
		fmt.Printf("database error %v", err)
		return
	}
	var vnameValue string
	for _, item := range res {
		vnameValue = item.Url + "         "
		vnameValue += item.Vname

		// 使用 vnameValue 进行后续操作
	}
	AS := service.ReScanWebTree{

		Code:      200,
		Msg:       "ok",
		UrlData:   res,
		JsData:    res,
		FormsData: res,
		Secret:    vnameValue,
	}
	c.JSON(http.StatusOK, AS)
}
