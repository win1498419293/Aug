package lib

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

func Connentdb() {
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var name int
	err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type=\"table\" AND name =\"Subdomain\"").Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	if name == 0 {
		//创建子域名表
		createsubdb := `CREATE TABLE IF NOT EXISTS Subdomain 
				(id INTEGER PRIMARY KEY,
				Src TEXT,
				Url  TEXT,
				Subdomain TEXT NOT NULL,
				Ip TEXT,
				Status TEXT,
				Waf TEXT,
				Title TEXT,
				Cdn TEXT,
				CreateTime TEXT);`
		_, err = db.Exec(createsubdb)
	}

	err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type=\"table\" AND name =\"Task\"").Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	if name == 0 {
		//创建任务表
		createTaskdb := `CREATE TABLE IF NOT EXISTS Task 
				(id INTEGER PRIMARY KEY,
				Src TEXT,
				Surl TEXT,
				Target TEXT,
				Url  TEXT,
				Service TEXT,
				Title TEXT,
				StatusCode TEXT,
				Banner TEXT,
				Webserver TEXT,
				Cms TEXT,
				Times TEXT);`
		_, err = db.Exec(createTaskdb)
	}

	err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type=\"table\" AND name =\"Vuln\"").Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	if name == 0 {
		//创建漏洞表
		createVulndb := `CREATE TABLE IF NOT EXISTS Vuln 
				(id INTEGER PRIMARY KEY,
				Src TEXT,
				CreateTime TEXT,
				Url TEXT,
				Payload  TEXT,
				Vname TEXT,
				Vabout TEXT);`
		_, err = db.Exec(createVulndb)
	}

	if err != nil {
		panic(err)
	}

}

func (spn SubdomainNameProperties) InsertTables() {

	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	stmt, err := db.Prepare("INSERT INTO Subdomain(Src,Url, Subdomain,Ip,Status,Waf,Title,Cdn,CreateTime) values(?, ?, ?, ?, ?, ?, ?, ?, ? )")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	Url := spn.Url
	Src := spn.Src
	Subdomain := spn.Subdomain
	Ip := spn.Ip
	Status := spn.Status
	Title := spn.Title
	Cdn := ""
	Waf := ""
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	CreateTime := timeStr
	res, err := stmt.Exec(Src, Url, Subdomain, Ip, Status, Waf, Title, Cdn, CreateTime)
	if err != nil {
		panic(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		panic(err)
	}
	fmt.Println("Last inserted ID:", id)
}

func (ag TxPortMapStruct) InsertTaskTables() {
	Connentdb()
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	stmt, err := db.Prepare("INSERT INTO Task(Src,Target,Surl,Url, Service,Title,StatusCode,Banner,Webserver,Cms,Times) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	Target := ag.Target
	Src := ag.Src
	Surl := ag.Surl
	Url := ag.Url
	Service := ag.Service
	Titel := ag.Title
	StatusCode := ag.StatusCode
	Banner := ag.Banner
	Webserver := ag.Webserver
	Times := ag.Times
	Cms := ""

	res, err := stmt.Exec(Src, Target, Surl, Url, Service, Titel, StatusCode, Banner, Webserver, Cms, Times)
	if err != nil {
		panic(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		panic(err)
	}
	fmt.Println("Last inserted ID:", id)
}

func (vs VulnProperties) InsertVulTables() {
	Connentdb()
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	stmt, err := db.Prepare("INSERT INTO Vuln(Src,CreateTime,Url, Payload,Vname,Vabout) values(?, ?, ?, ?, ?, ?)")
	if err != nil {
		panic(err)
	}
	defer stmt.Close()
	Src := vs.Src
	CreateTime := vs.CreateTime
	Url := vs.Url
	Payload := vs.Payload
	Vname := vs.Vname
	Vabout := vs.Vabout

	res, err := stmt.Exec(Src, CreateTime, Url, Payload, Vname, Vabout)
	if err != nil {
		panic(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		panic(err)
	}
	fmt.Println("Last inserted ID:", id)
}

func SelectSubdmaindb(sr, url string) (map[int]string, map[int]string) {
	TableResultMap := make(map[string]string)
	checkcdn := make(map[int]string)
	checkwaf := make(map[int]string)
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	var rows *sql.Rows
	urls := "%" + url + "%"
	if sr == "" || url == "" {
		rows, err = db.Query("SELECT * FROM Subdomain")
	} else {
		rows, err = db.Query("SELECT   * FROM Subdomain where Src=? and Url like ? ", sr, urls)
	}
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	i := 0
	lastip := ""
	for rows.Next() {
		var id int
		var src string
		var url string
		var subdomain string
		var ip string
		var status string
		var title string
		var cdn string
		var waf string
		var createtime string
		err = rows.Scan(&id, &src, &url, &subdomain, &ip, &status, &waf, &title, &cdn, &createtime)
		if err != nil {
			panic(err)
		}
		TableResultMap["id"] = string(id)
		TableResultMap["src"] = src
		TableResultMap["url"] = url
		TableResultMap["subdomain"] = subdomain
		TableResultMap["ip"] = ip
		TableResultMap["status"] = status
		TableResultMap["waf"] = waf
		TableResultMap["title"] = title
		TableResultMap["cdn"] = cdn
		TableResultMap["createtime"] = createtime
		//fmt.Println(id, url, subdomain, ip, port, status, title)
		if i < 100 {
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("Recovered:", r)
				}
			}()
			//waf检测
			wafflag, wafname := Wafcheck(url)

			//存在waf则保存waf名称
			if wafflag {
				//updateSubdomain("Waf", "True", id)
				checkwaf[id] = wafname
			}
			// 判断是否跟上一个ip是一样的，同ip跳过，不同ip进入端口扫描
			if subdomain != lastip {
				lastip = subdomain
				cdnflag, _ := Cdncheck(subdomain)
				if cdnflag {
					//updateSubdomain("Cdn","True",id))
					checkcdn[id] = "True"
				} else {
					//updateSubdomain("Cdn", "False",id)
					checkcdn[id] = "False"
				}
				i++
			}
		}
	}
	return checkcdn, checkwaf
}

func SelectAllTaskdb(params ...string) map[int]map[string]string {
	TxPortResultMap := make(map[int]map[string]string)
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	ColumnName := params[0]
	Field := params[1]
	sr := " "
	url := ""
	if len(params) >= 2 {
		sr = params[2]
		url = params[3]
	}
	var rows *sql.Rows
	urls := "%" + url + "%"
	if Field == "" || ColumnName == "" {
		rows, err = db.Query("SELECT * FROM Task")
	} else {
		comm := fmt.Sprintf("SELECT * FROM Task where %s=%q and src=%q and Surl like %q ", ColumnName, Field, sr, urls)
		rows, err = db.Query(comm, Field)
	}
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var id string
		var src string
		var surl string
		var target string
		var url string
		var service string
		var title string
		var statusCode string
		var banner string
		var webserver string
		var cms string
		var times string
		err = rows.Scan(&id, &src, &surl, &target, &url, &service, &statusCode, &banner, &webserver, &title, &cms, &times)
		if err != nil {
			panic(err)
		}
		if i > 10 {
			break
		}
		TxPortResultMap[i] = make(map[string]string)
		TxPortResultMap[i]["id"] = id
		TxPortResultMap[i]["src"] = src
		TxPortResultMap[i]["surl"] = surl
		TxPortResultMap[i]["target"] = target
		TxPortResultMap[i]["url"] = url
		TxPortResultMap[i]["service"] = service
		TxPortResultMap[i]["title"] = title
		TxPortResultMap[i]["statusCode"] = statusCode
		TxPortResultMap[i]["banner"] = banner
		TxPortResultMap[i]["webserver"] = webserver
		TxPortResultMap[i]["cms"] = cms
		TxPortResultMap[i]["times"] = times
		//fmt.Println(id, target, url, service, title, statusCode, banner, webserver, times)
		i++
	}

	return TxPortResultMap
}

// 获取子域名表数据
func SelectAllSubdmaindb(params ...string) map[int]map[string]string {
	TableResultMap := make(map[int]map[string]string)
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	ColumnName := params[0]
	Field := params[1]
	sr := " "
	url := " "
	if len(params) > 2 {
		sr = params[2]
		url = params[3]

	}
	var rows *sql.Rows
	urls := "%" + url + "%"
	if Field == "" || ColumnName == "" {
		rows, err = db.Query("SELECT * FROM Subdomain where Src=?", sr)
	} else {
		comm := fmt.Sprintf("SELECT * FROM Subdomain where %s=%q and src=%q and Url like %q ", ColumnName, Field, sr, urls)
		rows, err = db.Query(comm, Field)
	}

	if err != nil {
		panic(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var id string
		var src string
		var url string
		var subdomain string
		var ip string
		var status string
		var title string
		var cdn string
		var waf string
		var createtime string
		err = rows.Scan(&id, &src, &url, &subdomain, &ip, &status, &waf, &title, &cdn, &createtime)
		if err != nil {
			panic(err)
		}
		if i > 10 {
			break
		}
		TableResultMap[i] = make(map[string]string)
		TableResultMap[i]["id"] = id
		TableResultMap[i]["src"] = src
		TableResultMap[i]["url"] = url
		TableResultMap[i]["subdomain"] = subdomain
		TableResultMap[i]["ip"] = ip
		TableResultMap[i]["status"] = status
		TableResultMap[i]["waf"] = waf
		TableResultMap[i]["title"] = title
		TableResultMap[i]["cdn"] = cdn
		TableResultMap[i]["createtime"] = createtime
		//fmt.Println(id, url, subdomain, ip, port, status, title)
		i++
	}

	return TableResultMap
}

func SelectVuln() map[int]map[string]string {
	TableResultMap := make(map[int]map[string]string)
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	rows, err := db.Query("SELECT  DISTINCT * FROM Vuln")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		TableResultMap[i] = make(map[string]string)
		var id, src, CreateTime, Url, Payload, Vname, Vabout string
		err = rows.Scan(&id, &src, &CreateTime, &Url, &Payload, &Vname, &Vabout)
		if err != nil {
			panic(err)
		}
		TableResultMap[i]["id"] = id
		TableResultMap[i]["src"] = src
		TableResultMap[i]["Url"] = Url
		TableResultMap[i]["CreateTime"] = CreateTime
		TableResultMap[i]["Payload"] = Payload
		TableResultMap[i]["Vname"] = Vname
		TableResultMap[i]["Vabout"] = Vabout
		i++
	}
	return TableResultMap
}

// 更新子域名表数据
func updateSubdomain(ColumnName, flag string, id int) {
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	comm := fmt.Sprintf("update Subdomain set %s=?  where id=?", ColumnName)
	stmt, err := db.Prepare(comm)
	if stmt == nil || err != nil {
		panic(err)
	}
	_, err = stmt.Exec(flag, id)
	if err != nil {
		panic(err)
	}
}

// 更新Task表数据
func updateTask(ColumnName, flag, url string) {
	db, err := sql.Open("sqlite3", "result/Subdomain.db")
	comm := fmt.Sprintf("update Task set %s=?  where url=?", ColumnName)
	stmt, err := db.Prepare(comm)
	if stmt == nil || err != nil {
		panic(err)
	}
	_, err = stmt.Exec(flag, url)
	if err != nil {
		panic(err)
	}
}
