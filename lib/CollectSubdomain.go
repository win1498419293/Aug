package lib

import (
	"bufio"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"log"
	"os"
	"os/exec"
)

type Charset string

type SubdomainNameProperties struct {
	//Id        string
	Url       string
	Subdomain string
	Ip        string
	Port      string
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
