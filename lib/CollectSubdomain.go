package lib

import (
	"bufio"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"log"
	"os"
	"os/exec"
	"time"
)

type Charset string

type SubdomainNameProperties struct {
	//Id        string
	Url       string
	Src       string
	Subdomain string
	Ip        string
	Status    string
	Title     string
}

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

// 不带输出返回结果
func Collect_Subdomain_un(sudbomain string) {
	OneForAllfile := Readyaml("OneForAll.OneForAllfile")
	sublog, err := os.OpenFile("log/ColSub.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	cmd := exec.Command("cmd", "/c", "python", "oneforall.py", "--target", sudbomain, "run")
	cmd.Dir = OneForAllfile
	err = cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	flags := cmd.Wait()
	if flags == nil {
		fmt.Println("运行结束")
	}
	//写入日志
	log.SetOutput(sublog)
}

// 带执行结果输出
func Collect_Subdomain(sudbomain string) {
	OneForAllfile := Readyaml("OneForAll.OneForAllfile")
	sublog, err := os.OpenFile("log/ColSub.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	cmd := exec.Command("cmd", "/c", "python", "oneforall.py", "--target", sudbomain, "run")
	cmd.Dir = OneForAllfile
	stdout, err := cmd.StdoutPipe()
	cmd.Start()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	in := bufio.NewScanner(stdout)
	for in.Scan() {
		cmdRe := ConvertByte2String(in.Bytes(), "GB18030")
		log.Println(cmdRe)
	}

	flags := cmd.Wait()
	if flags == nil {
		fmt.Println("运行结束")
	}
	log.SetOutput(sublog)

}

// subfinder 子域名收集
func Subfinder(sudbomain string) []string {
	now := time.Now()
	currentData := now.Format("2006-01-02")
	sublog, err := os.OpenFile("log/ColSub.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	Subfinderfile := Readyaml("Subfinder.Subfinderexe")
	resultFilePath := Readyaml("Subfinder.resultFilePath")

	cmd := exec.Command("cmd", "/c", "subfinder -d "+sudbomain+" -silent| httpx -title -tech-detect -status-code  -ip -o result\\"+currentData+sudbomain+".txt")
	cmd.Dir = Subfinderfile
	err = cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	flags := cmd.Wait()
	if flags == nil {
		fmt.Println("Subfinder子域名收集结束")
	}

	jssensitivedatas := []string{}
	resultFilePaths := fmt.Sprintf(resultFilePath+"%s.txt", currentData+sudbomain)
	resultFile, err := os.Stat(resultFilePaths)
	if err == nil && resultFile.Size() > 0 {
		//获取扫描结果
		item := Readfile(resultFilePaths)
		for _, value := range item {
			jssensitivedatas = append(jssensitivedatas, value)
		}
	}

	//写入日志
	log.SetOutput(sublog)
	//去重
	JsSensitiveData := removeDuplicateElement(jssensitivedatas)
	return JsSensitiveData
}

// 解决中文乱码
func ConvertByte2String(byte []byte, charset Charset) string {
	var str string
	switch charset {
	case GB18030:
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}
	return str
}
