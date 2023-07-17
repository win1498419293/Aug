package service

import (
	"Aug/web/app/Models"
	"Aug/web/database"
	"fmt"
	"strings"
)

type ApiScanManagerAddReq Models.Cusinfo

type ResAPiScanManagerInfo Models.ResAPiScanManagerInfo

type Subdomain Models.Subdomain
type Task Models.Task
type Vuln Models.Vuln
type ResPortInfo Models.ResPortInfo

type Firminfo Models.Firminfo

type Webinfo Models.Webinfo

type Manufacturerinfo Models.Manufacturerinfo

type WebTreeInfo Models.WebTreeInfo

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

// 子域名表信息集合
type Subdomaininfo struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data []Subdomain `json:"data"`
}

// 厂商信息
type Srcinfo struct {
	Code int                `json:"code"`
	Msg  string             `json:"msg"`
	Data []Manufacturerinfo `json:"data"`
}

// web页面信息集合
type ResWebinfo struct {
	Code int       `json:"code"`
	Msg  string    `json:"msg"`
	Data []Webinfo `json:"data"`
}

// 端口页面信息集合
type Portinfo struct {
	Code int           `json:"code"`
	Msg  string        `json:"msg"`
	Data []ResPortInfo `json:"data"`
}

// 厂商管理 模糊分页查询返回数据所需信息
type ResAPiScanManager struct {
	Code  int                     `json:"code"`
	Msg   string                  `json:"msg"`
	Count int64                   `json:"count"`
	Data  []ResAPiScanManagerInfo `json:"data"`
}

// 查询num行数所用
type PortInfo struct {
	Target string
	url    string
}

// Findall 查询添加的厂商信息
func (ManagerAdd *ApiScanManagerAddReq) Scanmanage() (admins []Models.Cusinfo, err error) {
	result := database.DB.Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}

// Findall 查询厂商管理 模糊分页查询返回数据所需具体信息
func (ras *ResAPiScanManagerInfo) Scandmoain() (admins []ResAPiScanManagerInfo, err error) {
	result := database.DB.Find(&admins)
	if result.Error != nil {
		return admins, err
	}
	return admins, err
}

// 查询厂商管理信息
func (ras *ResAPiScanManagerInfo) Managers() (admins []ResAPiScanManagerInfo, err error) {
	admins, err = QueryColumn()
	if err != nil {
		return admins, err
	}
	return admins, err
}

// 查询端口页面信息
func (ras *ResPortInfo) GetPorts() (admins []ResPortInfo, err error) {
	admins, err = Queryport()
	if err != nil {
		return admins, err
	}
	return admins, err
}

// 查询web页面信息
func (ras *Webinfo) Getwebinfo() (admins []Webinfo, err error) {
	admins, err = Querywebinfo()
	if err != nil {
		return admins, err
	}
	return admins, err
}

// // 查询厂商域名信息
func (ras *Manufacturerinfo) GetManufacturerinfo() (admins []Manufacturerinfo, err error) {
	admins, err = GetManufacturerinfo()
	if err != nil {
		return admins, err
	}
	return admins, err
}

// 查询子域名表信息
func (sub *Subdomain) GetSubinfo() (admins []Subdomain, err error) {
	result := database.DB.Table("Subdomain").Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}

// 查询任务表信息
func (sub *Task) GetTaskinfo() (admins []Task, err error) {
	result := database.DB.Table("Task").Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}

// 查询漏洞表信息
func (sub *Vuln) GetVulninfo() (admins []Vuln, err error) {
	result := database.DB.Table("Vuln").Find(&admins)
	if result.Error != nil {
		err = result.Error
		return admins, err
	}
	return admins, err
}

// 查询厂商数据信息
func (fi *Firminfo) GetFirminfo() (res []Firminfo, err error) {
	var sub []Firminfo

	err = database.DB.Raw("SELECT Subdomain, id, Src, Port FROM `Subdomain`").Scan(&sub).Error
	if err != nil {
		fmt.Println(err)
		return res, err
	}

	for i := range sub {
		err = database.DB.Raw("SELECT Times FROM `Task` WHERE id = ?", sub[i].Id).Scan(&sub[i].Time).Error
		if err != nil {
			fmt.Println(err)
			return res, err
		}

		err = database.DB.Raw("SELECT Url FROM `Task` WHERE id = ?", sub[i].Id).Scan(&sub[i].Web).Error
		if err != nil {
			fmt.Println(err)
			return res, err
		}

		err = database.DB.Raw("SELECT Vname FROM `Vuln` WHERE id = ?", sub[i].Id).Scan(&sub[i].Vuln).Error
		if err != nil {
			fmt.Println(err)
			return res, err
		}
	}

	res = append(res, sub...)
	return res, err
}

// 查询厂商管理信息
func QueryColumn() (res []ResAPiScanManagerInfo, err error) {
	var sub []ResAPiScanManagerInfo
	var num []string
	err = database.DB.Raw("SELECT DISTINCT Src FROM `Task`").Scan(&num).Error
	err = database.DB.Raw("SELECT DISTINCT Src FROM `Task` ").Scan(&sub).Error
	for i := range num {
		sub[i].Id = i
		err = database.DB.Raw("SELECT DISTINCT Src FROM `Task` WHERE Src =? ", num[i]).Scan(&sub[i].CusName).Error
		err = database.DB.Raw("SELECT Count(Subdomain) FROM `Subdomain` WHERE Src =?", num[i]).Scan(&sub[i].CusSudDomainNum).Error
		err = database.DB.Raw("SELECT Count(Port) FROM `Subdomain` WHERE Src =?", num[i]).Scan(&sub[i].CusPortNum).Error
		err = database.DB.Raw("SELECT Count(Url) FROM `Task` WHERE Src =?", num[i]).Scan(&sub[i].CusWebNum).Error
		err = database.DB.Raw("SELECT Count(id) FROM `Vuln` WHERE Src =?", num[i]).Scan(&sub[i].CusVulNum).Error
	}
	res = append(res, sub...)
	return res, err
}

// 查询端口页面信息集合
func Queryport() (res []ResPortInfo, err error) {
	var sub []ResPortInfo
	var num []PortInfo
	err = database.DB.Raw("SELECT DISTINCT Target,url  FROM `Task`").Scan(&num).Error
	err = database.DB.Raw("SELECT DISTINCT Target,url  FROM `Task` ").Scan(&sub).Error
	for i := range sub {
		sub[i].Id = i
		err = database.DB.Raw("SELECT  Src FROM `Task` WHERE Target =? ", num[i].Target).Scan(&sub[i].CusName).Error
		err = database.DB.Raw("SELECT Target FROM `Task`").Scan(&sub[i].Port).Error
		err = database.DB.Raw("SELECT Banner FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].Banner).Error
		err = database.DB.Raw("SELECT Times FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].Times).Error
		err = database.DB.Raw("SELECT Service FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].Service).Error
		sub[i].Ip = strings.Split(num[i].Target, ":")[0]
		sub[i].Port = strings.Split(num[i].Target, ":")[1]

	}
	res = append(res, sub...)
	return res, err
}

// 查询web页面信息集合
func Querywebinfo() (res []Webinfo, err error) {
	var sub []Webinfo
	var num []PortInfo
	err = database.DB.Raw("SELECT DISTINCT Target,url  FROM `Task`").Scan(&num).Error
	err = database.DB.Raw("SELECT DISTINCT Target,url  FROM `Task` ").Scan(&sub).Error
	for i := range sub {
		sub[i].Id = i
		err = database.DB.Raw("SELECT  Src FROM `Task` WHERE Target =? ", num[i].Target).Scan(&sub[i].Src).Error
		err = database.DB.Raw("SELECT DISTINCT Title FROM `Task`  WHERE Target =? ", num[i].Target).Scan(&sub[i].Title).Error
		err = database.DB.Raw("SELECT url FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].Url).Error
		err = database.DB.Raw("SELECT DISTINCT StatusCode FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].StatusCode).Error
		err = database.DB.Raw("SELECT Cms FROM `Task` WHERE Target =?", num[i].Target).Scan(&sub[i].Cms).Error
		sub[i].Length = "23"
	}
	res = append(res, sub...)
	return res, err
}

// // 查询厂商域名信息
func GetManufacturerinfo() (res []Manufacturerinfo, err error) {
	var sub []Manufacturerinfo
	var num []Manufacturerinfo
	err = database.DB.Raw("SELECT DISTINCT Url  FROM `Subdomain`").Scan(&num).Error
	err = database.DB.Raw("SELECT DISTINCT Url  FROM `Subdomain` ").Scan(&sub).Error
	for i := range sub {
		sub[i].Id = i
		err = database.DB.Raw("SELECT  Src FROM `Subdomain`   WHERE Url =? ", num[i].Url).Scan(&sub[i].Src).Error
		err = database.DB.Raw("SELECT DISTINCT Url FROM `Subdomain`  WHERE Url =? ", num[i].Url).Scan(&sub[i].Url).Error
		err = database.DB.Raw("SELECT DISTINCT CreateTime FROM `Subdomain`  WHERE Url =? ", num[i].Url).Scan(&sub[i].Times).Error

	}
	res = append(res, sub...)
	return res, err
}

func (vs WebTreeInfo) Getvulninfo(url string) (res []WebTreeInfo, err error) {
	urls := "%" + url + "%"
	comm := fmt.Sprintf("SELECT Url,Vname FROM Vuln where url like %q ", urls)
	err = database.DB.Raw(comm).Scan(&res).Error
	return res, err
}
