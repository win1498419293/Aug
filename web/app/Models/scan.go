package Models

import (
	"Aug/web/database"
	"gorm.io/gorm"
)

// 添加主域名所需信息
type ScanDomainApiAddReq struct {
	CusName string `v:"required#厂商名不能为空"`
	Domain  string `v:"required#主域名不能为空"`
}

// 添加厂商所需信息
type Cusinfo struct {
	gorm.Model
	Id      int    `gorm:"primary_key;auto_increment"`
	CusName string `json:"CusName"`
	Domain  string `json:"Domain"`
}

// 删除厂商所需信息
type ApiScanManagerDeleteReq struct {
	CusName string `v:"required#厂商名不能为空"`
}

// 厂商管理 模糊分页查询返回数据所需信息
type APiScanManager struct {
	Code  int       `json:"code"`
	Msg   string    `json:"msg"`
	Count int64     `json:"count"`
	Data  []Cusinfo `json:"data"`
}

// 厂商管理 模糊分页查询返回数据所需具体信息
type ResAPiScanManagerInfo struct {
	Id              int    `json:"id"`
	CusName         string `json:"cus_name"`
	CusSudDomainNum int    `json:"cus_subdomain_num"`
	CusPortNum      int    `json:"cus_port_num"`
	CusWebNum       int    `json:"cus_web_num"`
	CusVulNum       int    `json:"cus_vul_num"`
}

// 厂商管理 模糊分页查询返回数据所需具体信息
type ResPortInfo struct {
	Id      int    `json:"id"`
	CusName string `json:"cus_name"`
	Ip      string `json:"ip"`
	Port    string `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	Times   string `json:"times"`
}

// 厂商管理表
type Manufacturerinfo struct {
	Id    int    `json:"id"`
	Src   string `json:"cus_name"`
	Url   string `json:"domain"`
	Flag  bool   `json:"flag"`
	Times string `json:"times"`
}

// 子域名表信息
type Subdomain struct {
	//gorm.Model        // 这里的配置可以让ORM 自动维护 时间戳字段，很爽有木有
	Id        int    `gorm:"primary_key;auto_increment" json:"id"`
	Src       string `json:"src"`
	Url       string `json:"url"`
	Subdomain string `json:"subdomain"`
	Ip        string `json:"ip"`
	Port      string `json:"port"`
	Status    string `json:"status"`
	Waf       string `json:"waf"`
	Title     string `json:"title"`
	Cdn       string `json:"cdn"`
}

// 任务表信息
type Task struct {
	//gorm.Model        // 这里的配置可以让ORM 自动维护 时间戳字段，很爽有木有
	Id         int    `gorm:"primary_key;auto_increment"`
	Src        string `json:"src"`
	Url        string `json:"url"`
	Target     string `json:"target"`
	Service    string `json:"service"`
	Title      string `json:"title"`
	StatusCode string `json:"statusCode"`
	Banner     string `json:"banner"`
	Webserver  string `json:"webserver"`
	Cms        string `json:"cms"`
	Times      string `json:"times"`
}

// 漏洞表信息
type Vuln struct {
	//gorm.Model        // 这里的配置可以让ORM 自动维护 时间戳字段，很爽有木有
	Id         int    `gorm:"primary_key;auto_increment"`
	Src        string `json:"src"`
	Url        string `json:"url"`
	CreateTime string `json:"createTime"`
	Payload    string `json:"payload"`
	Vname      string `json:"vname"`
	Vabout     string `json:"vabout"`
}

// 厂商信息
type Firminfo struct {
	Id        int
	Src       string
	Subdomain string
	Port      string
	Web       string
	Vuln      string
	Time      string
}

// 厂商管理表
type ResManufacturerinfo struct {
	Code int                `json:"code"`
	Msg  string             `json:"msg"`
	Data []Manufacturerinfo `json:"data"`
}

// 投递web扫描消息格式
type NsqPushWeb struct {
	CusName     string
	SubDomain   []string
	ServiceName string
	Port        int
	Ip          string
}

type Webinfo struct {
	Id         int    `json:"id"`
	Src        string `json:"src"`
	Title      string `json:"title"`
	Url        string `json:"url"`
	StatusCode string `json:"statuscode"`
	Length     string `json:"length"`
	Cms        string `json:"cms"`
	Flag       bool   `json:"flag"`
}

// 返回指定url的爬虫结果
type ScanWebTreeReq struct {
	Url string `v:"required#参数不能为空"`
}

// web爬虫返回结果
type ReScanWebTree struct {
	Code      int           `json:"code"`
	Msg       string        `json:"msg"`
	UrlData   []WebTreeInfo `json:"urldata"`
	JsData    []WebTreeInfo `json:"jsdata"`
	FormsData []WebTreeInfo `json:"formsdata"`
	Secret    string        `json:"secret"`
	Images    string        `json:"images"`
}

// web爬虫详细结果
type WebTreeInfo struct {
	Vname string `json:"vname"`
	Url   string `json:"url"`
}

// 返回信息状态
type Scanmsg struct {
	Status  bool   `json:"status"  binding:"required"`
	Code    int    `json:"code"  binding:"required"`
	Message string `json:"msg"  binding:"required"`
	Error   error  `json:"error"  binding:"required"`
}

// 漏洞表信息
type Vulninfo struct {
	Id      int    `json:"id"`
	Url     string `json:"url"`
	Payload string `json:"payload"`
	Vname   string `json:"vname"`
	Vabout  string `json:"vabout"`
}

// 端口扫描信息
type PotrScaninfo struct {
	flag  bool   `json:"flag"`
	Ip    string `json:"ip"`
	Ports string `json:"ports"`
	Url   string `json:"url"`
	Src   string `json:"src"`
}

// Web扫描信息
type WebScaninfo struct {
	Flag   bool   `json:"flag"`
	Url    string `json:"url"`
	Src    string `json:"src"`
	Thread int    `json:"thread"`
}

func (ManagerInfo *ResAPiScanManagerInfo) ApiManagerInfo() (id int, err error) {
	database.DB.AutoMigrate(&ManagerInfo) //  这里的DB变量是 database 包里定义的，Create 函数是 gorm包的创建数据API
	result := database.DB.Create(&ManagerInfo)
	id = ManagerInfo.Id
	if result.Error != nil {
		err = result.Error
		return 0, err
	}
	return id, err // 返回新建数据的id 和 错误信息，在控制器里接收
}

// 添加厂商
func (ManagerAdd *Cusinfo) ManageInsert() (err error) {
	database.DB.AutoMigrate(&ManagerAdd) //  这里的DB变量是 database 包里定义的，Create 函数是 gorm包的创建数据API
	result := database.DB.Create(&ManagerAdd)
	if result.Error != nil {
		err = result.Error
	}

	return err // 返回新建数据的id 和 错误信息，在控制器里接收
}

// 添加厂商域名信息
func (ManagerAdd *Manufacturerinfo) ManufacturerinfoInsert() (err error) {
	database.DB.AutoMigrate(&ManagerAdd) //  这里的DB变量是 database 包里定义的，Create 函数是 gorm包的创建数据API
	result := database.DB.Create(&ManagerAdd)
	if result.Error != nil {
		err = result.Error
	}
	return err // 返回新建数据的id 和 错误信息，在控制器里接收
}
