package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/fatih/color"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Autocrawlergo struct {
	ReqList       []ReqList    `json:"req_list"`
	AllReqList    []AllReqList `json:"all_req_list"`
	AllDomainList []string     `json:"all_domain_list"`
	SubDomainList []string     `json:"sub_domain_list"`
}

type ReqList struct {
	URL     string  `json:"url"`
	Method  string  `json:"method"`
	Headers Headers `json:"headers"`
	Data    string  `json:"data"`
	Source  string  `json:"source"`
}
type Headers struct {
	Accept     string `json:"Accept"`
	Referer    string `json:"Referer"`
	SpiderName string `json:"Spider-Name"`
	UserAgent  string `json:"User-Agent"`
}
type AllReqList struct {
	URL     string  `json:"url"`
	Method  string  `json:"method"`
	Headers Headers `json:"headers,omitempty"`
	Data    string  `json:"data"`
	Source  string  `json:"source"`
}

type AutoXray []struct {
	CreateTime int64  `json:"create_time"`
	Detail     Detail `json:"detail"`
	Plugin     string `json:"plugin"`
	Target     Target `json:"target,omitempty"`
}
type Param struct {
}
type Extra struct {
	Param Param `json:"param"`
}
type Detail struct {
	Addr     string     `json:"addr"`
	Payload  string     `json:"payload"`
	Snapshot [][]string `json:"snapshot"`
	Extra    Extra      `json:"extra"`
}

type Params struct {
	Position string   `json:"position"`
	Path     []string `json:"path"`
}
type Target struct {
	URL    string   `json:"url"`
	Params []Params `json:"params"`
}

func finderjs(url string) []string {

	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))
	//ip或者url
	dom := ""

	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}
	flag := chechstart()
	if flag {
		//读取存在的xray漏洞报告
		startxray(dom)
	}

	jsfinderresultFilePath := Readyaml("JSFinderPlus.resultFilePath")
	jsfinderfile := Readyaml("JSFinderPlus.JSFinderPlusfile")
	fingerjslog, err := os.OpenFile("log/fingerjs.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	com := " python JSFinderPlus.py --proxy-http 127.0.0.1:7777  -u " + url
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = jsfinderfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("JSFinderPlus cmd.Run() failed with %s\n", err, stderr.String())
	}

	flags := cmd.Wait()

	if flags == nil {
		log.Println("运行结束")
	}

	//jsfender扫描结果报告路径
	jsfinderresult := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		jsfinderresult = jsfinderresultFilePath + domain + ".html"
		dom = domain
	} else {
		jsfinderresult = jsfinderresultFilePath + string(ip) + ".html"
		dom = string(ip)
	}

	//判断扫描报告是否生成
	resultfile, err := os.Stat(jsfinderresult)
	jssensitivedatas := []string{}
	if err == nil && resultfile.Size() > 0 {
		//读取jsfinder扫描报告html
		txts := Readhtml(jsfinderresult)
		//根据.分割匹配
		splitip := strings.Split(dom, ".")
		mat := fmt.Sprintf("http:\\/\\/%s\\.%s[^\\s]+", splitip[0], splitip[1])
		re := regexp.MustCompile(mat)
		for i := 0; i < len(txts)-1; i++ {
			matches := re.FindAllString(txts[i], -1)
			if len(matches) > 0 {
				jssensitivedatas = append(jssensitivedatas, strings.Trim(matches[0], `"`))
				//fmt.Println(txts[i])
			}

		}
	}
	//去重
	JsSensitiveData := removeDuplicateElement(jssensitivedatas)
	log.SetOutput(fingerjslog)
	return JsSensitiveData
}

// 数组切片去重
func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// 调用CrawlerGo对传入的站点进行爬取url爬取
func startCrawlerGo(url string, thread int) string {
	crawlergoresultFilePath := Readyaml("crawlergo.resultFilePath")
	crawlergoexe := Readyaml("crawlergo.crawlergoexe")
	resultfile, err := os.Stat(crawlergoresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(crawlergoresultFilePath, os.ModePerm)
	}
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))
	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}
	xrayreport := ""
	flag := chechstart()
	if flag {
		//读取存在的xray漏洞报告
		xrayreport = startxray(dom)
	}

	now := time.Now()
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	currentData := now.Format("2006-01-02")
	chromePath := Readyaml("ChromePath.chromePathexe")
	outreport := fmt.Sprintf("%s%s.json", currentData, dom)
	cmd := exec.Command("./crawlergo", "-c", chromePath, "-t", strconv.Itoa(thread), "--output-json", "result\\"+outreport, "--push-to-proxy", "http://127.0.0.1:7777", url)
	cmd.Dir = crawlergoexe
	err = cmd.Start()
	if err != nil {
		log.Fatalf("CrawlerGo cmd.Run() failed with %s\n", err)
	}

	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}

	resultFilePath := crawlergoresultFilePath + outreport
	resultFile, err := os.Stat(resultFilePath)
	//文件存在且存在内容时读取内容
	if err == nil && resultFile.Size() > 0 {
		i := 0
		if resultFile.Size() > 0 {
			file, err := os.Open(resultFilePath)
			if err != nil {
				fmt.Println(err, 1123123)
			}
			defer file.Close()
			decoder := json.NewDecoder(file)
			for {
				var craw Autocrawlergo
				err := decoder.Decode(&craw)
				if err != nil {
					break
				}
				//fmt.Println(len(craw.ReqList))
				//fmt.Println(craw.ReqList[i].URL)
				i++
			}
		}
	}
	log.SetOutput(XScanlog)
	return xrayreport
}

// xray读取html报告漏洞信息
func GetXrayHtmlResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	xrayhtml := make(map[int]map[string]string)
	reg, _ := regexp2.Compile(`(?<=addr":")(.+?)(?=","payload)`, 0)
	pluginre, _ := regexp2.Compile(`(?<=plugin":")(.+?)(?=",")`, 0)
	payloa, _ := regexp2.Compile(`(?<=payload":")(.*?)(?=",\"snapshot)`, 0)
	createTim, _ := regexp2.Compile(`(?<=create_time":)(.+?)(?=,"de)`, 0)
	targets, _ := regexp2.Compile(`(?<=url":")(.+?)(?=/"}})`, 0)
	for i := 0; i < len(item)-1; i++ {
		xrayhtml[i] = make(map[string]string)
		// 提取目标数据
		m, _ := reg.FindStringMatch(item[i])
		if m != nil {
			xrayhtml[i]["addr"] = m.String()
		}
		// 提取插件数据
		plugin, _ := pluginre.FindStringMatch(item[i])
		if plugin != nil {
			xrayhtml[i]["plugin"] = plugin.String()
		}
		// 提取 payload 数据
		paylo, _ := payloa.FindStringMatch(item[i])
		if paylo != nil {
			xrayhtml[i]["paylo"] = paylo.String()
		}

		// 提取创建时间数据
		createTi, _ := createTim.FindStringMatch(item[i])
		if createTi != nil {
			//时间戳转时间
			time2, _ := strconv.ParseInt(createTi.String(), 10, 64)
			timestamp := time2
			seconds := timestamp / 1000
			nanoseconds := (timestamp % 1000) * 1000000
			t := time.Unix(seconds, nanoseconds)
			formattedTime := t.Format("2006-01-02 15:04:05")
			xrayhtml[i]["createTi"] = formattedTime
		}
		// 提取target数据
		target, _ := targets.FindStringMatch(item[i])
		if target != nil {
			xrayhtml[i]["target"] = target.String()
			//fmt.Println(target.String())
		}
	}
	return xrayhtml
}

// xray读取json格式报告漏洞信息
func GetXrayJsonResult(path string) map[int]map[string]string {
	xrayjson := make(map[int]map[string]string)
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var xray AutoXray
	err = decoder.Decode(&xray)
	for i := 0; i < len(xray); i++ {
		if err != nil {
			break
		}
		xrayjson[i] = make(map[string]string)
		xrayjson[i]["create_time"] = strconv.Itoa(int(xray[i].CreateTime))
		xrayjson[i]["addr"] = xray[i].Detail.Addr
		xrayjson[i]["Payload"] = xray[i].Detail.Payload
		xrayjson[i]["plugin"] = xray[i].Plugin
		xrayjson[i]["target"] = xray[i].Target.URL
	}
	return xrayjson
}
func chechstart() bool {
	flag := true
	// 构建命令和参数
	cmd := exec.Command("cmd.exe", "/C", "tasklist", "|", "findstr", "/i", "xray.exe")
	// 执行命令并获取输出结果
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("启动Xray:")
	}
	// 将输出结果转换为字符串并打印

	if strings.Contains(string(output), "xray.exe") {
		flag = false
	} else {
		flag = true
	}
	return flag
}

func startxray(host string) string {
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(host))
	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		dom = host
	} else {
		dom = string(ip)
	}
	xrayresultFilePath := Readyaml("xray.resultFilePath")
	xrayexe := Readyaml("xray.xrayexe")
	resultfile, err := os.Stat(xrayresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(xrayresultFilePath, os.ModePerm)
	}
	now := time.Now()
	currentData := now.Format("2006-01-02")
	outreport := fmt.Sprintf("%s%s.html", currentData, dom)
	com := "./xray webscan --listen 0.0.0.0:7777 --html-output  result\\" + outreport
	cmd := exec.Command("cmd", "/c", "start "+com)
	cmd.Dir = xrayexe
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Start()
	if err != nil {
		log.Println(err.Error(), stderr.String())
	} else {
		log.Println(out.String())
	}
	xrayreport := xrayresultFilePath + currentData + host + ".html"
	log.SetOutput(XScanlog)
	return xrayreport
}

func nucleiscan(url string, flag bool) {
	c := color.New()
	c.Add(color.FgRed, color.Bold)
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}
	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}
	nucleiresultFilePath := Readyaml("nuclei.resultFilePath")
	nucleiexe := Readyaml("nuclei.nucleiexe")
	resultfile, err := os.Stat(nucleiresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(nucleiresultFilePath, os.ModePerm)
	}
	now := time.Now()
	currentData := now.Format("2006-01-02")
	cmd := exec.Command("./nuclei.exe", "-u", url, "-json", "-o", "result\\"+currentData+dom+".json")
	cmd.Dir = nucleiexe
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("nucleiscan cmd.Run() failed with %s\n", err, stderr.String())
	}
	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := nucleiresultFilePath + currentData + dom + ".json"
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		if resultFile.Size() > 0 {
			gnr := GetNucleiJsonResult(resultFilePath)
			for _, vaule := range gnr {
				c.Println("Url:  ", vaule["url"], " vname: ", vaule["name"], " description: ", vaule["description"])
				fmt.Println()
				if flag {
					properties := VulnProperties{
						CreateTime: vaule["timestamp"],
						Url:        vaule["url"],
						Payload:    vaule["curlcommand"],
						Vname:      vaule["name"],
						Vabout:     vaule["description"],
					}
					properties.InsertVulTables()
				}
			}
		}
	}
	log.SetOutput(XScanlog)
}

func GetNucleiJsonResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	njr := make(map[int]map[string]string)
	timestamps, _ := regexp2.Compile(`(?<=timestamp":")(.+?)(?=",")`, 0)
	urls, _ := regexp2.Compile(`(?<=matched-at":")(.+?)(?=",")`, 0)
	curlcommands, _ := regexp2.Compile(`(?<=curl-command":")(.+?)(?=",")`, 0)
	names, _ := regexp2.Compile(`(?<=name":")(.+?)(?=",")`, 0)
	descriptions, _ := regexp2.Compile(`(?<=description":")(.+?)(?=",")`, 0)

	for i := 0; i < len(item); i++ {
		njr[i] = make(map[string]string)
		// 提取目标数据
		timestamp, _ := timestamps.FindStringMatch(item[i])
		if timestamp != nil {
			inputTime := timestamp.String()
			layout := "2006-01-02T15:04:05.9999999-07:00"
			outputLayout := "2006-01-02 15:04:05"
			t, err := time.Parse(layout, inputTime)
			if err != nil {
				fmt.Println("无法解析时间:", err)
			}

			// 格式化为输出时间字符串
			outputTime := t.Format(outputLayout)
			njr[i]["timestamp"] = outputTime
		}
		// 提取插件数据
		url, _ := urls.FindStringMatch(item[i])
		if url != nil {
			njr[i]["url"] = url.String()
		}
		// 提取 payload 数据
		curlcommand, _ := curlcommands.FindStringMatch(item[i])
		if curlcommand != nil {
			njr[i]["curlcommand"] = curlcommand.String()
		}
		// 提取 payload 数据
		name, _ := names.FindStringMatch(item[i])
		if name != nil {
			njr[i]["name"] = name.String()
		}
		// 提取 payload 数据
		description, _ := descriptions.FindStringMatch(item[i])
		if description != nil {
			njr[i]["description"] = description.String()
		}
	}
	return njr
}

func GetNucleiResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	nucleitxt := make(map[int]map[string]string)
	for i := 0; i < len(item); i++ {
		nucleitxt[i] = make(map[string]string)
		datas := strings.Split(item[i], " ")
		if len(datas) > 6 {
			nucleitxt[i]["time"] = datas[0] + " " + datas[1]
			nucleitxt[i]["service"] = datas[2]
			nucleitxt[i]["http"] = datas[3]
			nucleitxt[i]["info"] = datas[4]
			nucleitxt[i]["url"] = datas[5]
			nucleitxt[i]["banner"] = datas[6]
		} else {
			nucleitxt[i]["time"] = datas[0] + " " + datas[1]
			nucleitxt[i]["service"] = datas[2]
			nucleitxt[i]["http"] = datas[3]
			nucleitxt[i]["info"] = datas[4]
			nucleitxt[i]["url"] = datas[5]
		}

	}
	return nucleitxt
}

func vulmapscan(url string, thread int, flag bool) {
	c := color.New()
	c.Add(color.FgRed, color.Bold)
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}

	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}

	vulmapresultFilePath := Readyaml("vulmap.resultFilePath")
	Vulmapfile := Readyaml("vulmap.vulmapfile")
	resultfile, err := os.Stat(vulmapresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(vulmapresultFilePath, os.ModePerm)
	}
	now := time.Now()
	currentData := now.Format("2006-01-02")
	com := "python vulmap.py -t " + strconv.Itoa(thread) + " -u " + url + " --output-json  result\\" + currentData + dom + ".txt"
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = Vulmapfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("vulmapscan cmd.Run() failed with %s\n", err, stderr.String())
	}
	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := fmt.Sprintf(vulmapresultFilePath+"%s.txt", currentData+dom)
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		gvr := GetVulmapJsonResult(resultFilePath)
		for _, vaule := range gvr {
			//fmt.Println(vaule["CreateTime"])
			//fmt.Println(vaule["Url"])
			//fmt.Println(vaule["Payload"])
			//fmt.Println(vaule["Plugin"])
			//fmt.Println(vaule["Description"])
			c.Println("Url:", vaule["Url"], "  Plugin:", vaule["Plugin"], " Description:", vaule["Description"])
			if flag {
				properties := VulnProperties{
					CreateTime: vaule["CreateTime"],
					Url:        vaule["Url"],
					Payload:    vaule["Payload"],
					Vname:      vaule["Plugin"],
					Vabout:     vaule["Description"],
				}
				properties.InsertVulTables()
			}
		}
	}
	log.SetOutput(XScanlog)
}

/*
func GetVulmapResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	vulmaptxt := make(map[int]map[string]string)
	txts := []string{}
	// 定义正则表达式
	re := regexp.MustCompile(`\[(.*?)\]`)

	// 提取中括号内的文字
	for i := 0; i < len(item); i++ {

		// 使用正则表达式查找所有匹配项
		matches := re.FindAllStringSubmatch(item[i], -1)
		// 提取中括号内的文字

		for _, match := range matches {
			//fmt.Println(match[1])
			txts = append(txts, match[1])
		}
		//等全部都追加上在读取
		if i >= len(item)-1 {

			j := 1 //计数 5刚好一行
			l := 1 //map计数
			//读取数组里的内容
			for k := 1; k < len(txts); k++ {
				vulmaptxt[l] = make(map[string]string)
				if j == 5 {
					vulmaptxt[l]["vname"] = txts[1]
					vulmaptxt[l]["cve"] = txts[2]
					vulmaptxt[l]["vtype"] = txts[3]
					vulmaptxt[l]["vulnclass"] = txts[4]
					l++
					j = 0
				}
				j++
			}
		}

	}
	return vulmaptxt
}


*/

// 获取vulmap扫描结果
func GetVulmapTxTResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	vulmaptxt := make(map[int]map[string]string)
	txts := make([]string, 0, len(item)*5)
	// 定义正则表达式
	re := regexp.MustCompile(`\[(.*?)\]`)
	// 提取中括号内的文字
	for _, line := range item {
		matches := re.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			txts = append(txts, match[1])
		}
	}
	for i := 0; i < len(txts)-1; i += 5 {
		vname := txts[i+1]
		cve := txts[i+2]
		vtype := txts[i+3]
		vulnclass := txts[i+4]
		vulmaptxt[(i/5)+1] = map[string]string{
			"vname":     vname,
			"cve":       cve,
			"vtype":     vtype,
			"vulnclass": vulnclass,
		}
	}
	return vulmaptxt
}

type Record struct {
	CreateTime int64 `json:"create_time"`
	Detail     struct {
		Author      string                 `json:"author"`
		Description string                 `json:"description"`
		Host        string                 `json:"host"`
		Param       map[string]interface{} `json:"param"`
		Payload     string                 `json:"payload"`
		Port        int                    `json:"port"`
		Request     string                 `json:"request"`
		Response    string                 `json:"response"`
		URL         string                 `json:"url"`
	} `json:"detail"`
	Plugin string `json:"plugin"`
	Target struct {
		URL string `json:"url"`
	} `json:"target"`
	VulnClass string `json:"vuln_class"`
}

func GetVulmapJsonResult(path string) map[int]map[string]string {
	// 读取JSON文件内容
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("无法读取JSON文件: %v\n", err)
	}

	// 解析JSON数据
	var records []Record
	err = json.Unmarshal(data, &records)
	if err != nil {
		fmt.Printf("无法解析JSON数据: %v\n", err)
	}
	vjr := make(map[int]map[string]string)
	// 打印读取到的记录
	for i := 0; i < len(records); i++ {
		if err != nil {
			break
		}
		vjr[i] = make(map[string]string)
		time2, _ := strconv.ParseInt(strconv.FormatInt(records[i].CreateTime, 10), 10, 64)
		timestamp := time2
		seconds := timestamp / 1000
		nanoseconds := (timestamp % 1000) * 1000000
		t := time.Unix(seconds, nanoseconds)
		formattedTime := t.Format("2006-01-02 15:04:05")
		//fmt.Println("Create Time:", record.CreateTime)
		//fmt.Println("Author:", record.Detail.Author)
		//fmt.Println("Description:", record.Detail.Description)
		//fmt.Println("Host:", record.Detail.Host)
		//fmt.Println("Param:", record.Detail.Param)
		//fmt.Println("Payload:", record.Detail.Payload)
		//fmt.Println("Port:", record.Detail.Port)
		//fmt.Println("Request:", record.Detail.Request)
		//fmt.Println("Response:", record.Detail.Response)
		//fmt.Println("URL:", record.Detail.URL)
		//fmt.Println("Plugin:", records[i].Plugin)
		//fmt.Println("Target URL:", record.Target.URL)
		//fmt.Println("Vulnerability Class:", record.VulnClass)
		vjr[i]["CreateTime"] = formattedTime
		vjr[i]["Url"] = records[i].Target.URL
		vjr[i]["Plugin"] = records[i].Plugin
		vjr[i]["Payload"] = records[i].Detail.Payload
		vjr[i]["Description"] = records[i].Detail.Description

	}
	return vjr
}

// flag 用来判断是否需要将扫描到的漏洞插入到数据库
func pocbomberscan(url string, thread int, flag bool) {

	c := color.New()
	c.Add(color.FgRed, color.Bold)
	now := time.Now()
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}
	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}
	pocbomberresultFilePath := Readyaml("POC_bomber.resultFilePath")
	pocbomberfile := Readyaml("POC_bomber.POC_bomberfile")
	resultfile, err := os.Stat(pocbomberresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(pocbomberresultFilePath, os.ModePerm)
	}
	currentData := now.Format("2006-01-02")
	currenttime := now.Format("2006-01-02 02:23:23")
	com := "python pocbomber.py -t " + strconv.Itoa(thread) + " -u " + url + " -o  result\\" + currentData + dom + ".txt"
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = pocbomberfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("pocbomberscan cmd.Run() failed with %s\n", err, stderr.String())
	}
	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := fmt.Sprintf(pocbomberresultFilePath+"%s.txt", currentData+dom)
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		gjr := GetPocbomberResult(resultFilePath)
		for _, vaule := range gjr {
			//fmt.Println(vaule["Name"])
			//fmt.Println(vaule["Vulnerable"])
			//fmt.Println(vaule["Url"])
			//fmt.Println(vaule["Payload"])
			//fmt.Println(vaule["About"])
			c.Println("Url:", vaule["Url"], "VName: ", vaule["Name"], "VAbout: ", vaule["About"])
			if flag {
				properties := VulnProperties{
					CreateTime: currenttime,
					Url:        vaule["Url"],
					Payload:    vaule["Payload"],
					Vname:      vaule["Name"],
					Vabout:     vaule["About"],
				}
				properties.InsertVulTables()
			}

		}
	}
	log.SetOutput(XScanlog)
}

// 获得Pocbomber扫描结果
func GetPocbomberResult(path string) map[int]map[string]string {
	item := Readhtml(path)
	pocbomtxt := make(map[int]map[string]string)
	for i := 0; i < len(item); i += 5 {
		//将Url: http://47.95.245.15:80 分割成 http://47.95.245.15:80
		Name := strings.Split(item[i], ": ")
		Vulnerable := strings.Split(item[i+1], ": ")
		Url := strings.Split(item[i+2], ": ")
		Payload := strings.Split(item[i+3], ": ")
		About := strings.Split(item[i+4], ": ")
		pocbomtxt[(i/5)+1] = map[string]string{
			"Name":       Name[1],
			"Vulnerable": Vulnerable[1],
			"Url":        Url[1],
			"Payload":    Payload[1],
			"About":      About[1],
		}
	}
	return pocbomtxt
}

func backfilescan(url string, thread int) {
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	BackFileScanresultFilePath := Readyaml("BackFileScan.resultFilePath")
	BackFileScanfile := Readyaml("BackFileScan.BackFileScanfile")
	now := time.Now()
	currentData := now.Format("2006-01-02")
	_, host := Urlchange(url)
	resultfile, err := os.Stat(BackFileScanresultFilePath)
	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(BackFileScanresultFilePath, os.ModePerm)
	}
	com := "python BackFileScan.py -t " + string(thread) + " -u " + url + " -o  result\\" + currentData + host + ".txt"
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = BackFileScanfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("backfilescan cmd.Run() failed with %s\n", err, stderr.String())
	}
	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := BackFileScanresultFilePath + currentData + host + ".txt"
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		//获取扫描结果
		item := GetKatanaResult(resultFilePath)
		for _, value := range item {
			value = strings.Replace(value, "\n", "", -1)
			color.Yellow("存在敏感文件：%s", value)
		}
	}
	log.SetOutput(XScanlog)
}

func dirsearchscan(url string, thread int) {
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	dirsearchresultFilePath := Readyaml("dirsearch.resultFilePath")
	dirsearchfile := Readyaml("dirsearch.dirsearchfile")
	resultfile, err := os.Stat(dirsearchresultFilePath)

	if !(err == nil && resultfile.Size() > 0) {
		os.Mkdir(dirsearchresultFilePath, os.ModePerm)
	}
	now := time.Now()
	currentData := now.Format("2006-01-02")
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}
	_, host := Urlchange(url)
	com := "python dirsearch.py -t " + strconv.Itoa(thread) + " -u " + url + " --random-agent -x 404 -r --max-recursion-depth 3 --recursion-status 200 --format plain -o result\\" + currentData + host + ".txt"
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = dirsearchfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("dirsearchscan cmd.Run() failed with %s\n", err, stderr.String())
	}
	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := dirsearchresultFilePath + currentData + host + ".txt"
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		//获取扫描结果
		item := GetKatanaResult(resultFilePath)
		var kl string
		for index, value := range item {
			if index > 1 {
				value = strings.Replace(value, "\n", "", -1)
				newvalue := strings.Split(value, " ")
				kl = newvalue[1] + newvalue[2] + newvalue[3] + newvalue[4] + newvalue[5] + newvalue[6]
				if kl != "0B" && newvalue[0] == "200" {
					color.Red("存在目录：%s", value)
				} else {
					color.Yellow("存在目录：%s", value)
				}
			}

		}
	}
	log.SetOutput(XScanlog)
}

func katanascan(url string) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("cdncheck出现错误:", err)
		}
	}()
	c := color.New()
	c.Add(color.FgRed, color.Bold)
	katanaresultFilePath := Readyaml("katana.resultFilePath")
	katanaexe := Readyaml("katana.katanaexe")
	XScanlog, err := os.OpenFile("log/XScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	regstr := `\d+\.\d+\.\d+\.\d+`   //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr) //编译正则表达式
	ip := reg.Find([]byte(url))

	//ip或者url
	dom := ""
	//如果匹配ip识别则获取host，否则获取ip
	if ip == nil {
		_, domain := Urlchange(url)
		dom = domain
	} else {
		dom = string(ip)
	}
	flag := chechstart()
	if flag {
		//读取存在的xray漏洞报告
		startxray(dom)
	}
	now := time.Now()
	currentData := now.Format("2006-01-02")
	//cmd 不带./

	cmd := exec.Command("cmd", "/C", "katana  -d 3 -u "+url+" -proxy http://127.0.0.1:7777 | URLPath64.exe > "+currentData+dom+".txt")
	cmd.Dir = katanaexe
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("katanascan cmd.Run() failed with %s\n", err, stderr.String())
	}

	flags := cmd.Wait()
	if flags == nil {
		log.Println("运行结束")
	}
	resultFilePath := fmt.Sprintf(katanaresultFilePath+"%s.txt", currentData+dom)
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		item := GetKatanaResult(resultFilePath)
		for _, value := range item {
			value = strings.Replace(value, "\n", "", -1)
			c.Println(value)
		}
	}
	log.SetOutput(XScanlog)
}

func GetKatanaResult(path string) []string {
	item := Readhtml(path)
	return item
}
