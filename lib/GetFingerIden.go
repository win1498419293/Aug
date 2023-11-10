package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type fingetiden struct {
	Url     string
	Title   string
	Cms     string
	Server  string
	Status  string
	Size    string
	Ip      string
	Iscdn   string
	Address string
	Isp     string
}

type Website struct {
	Url        string
	Title      string
	Cms        string
	Server     string
	Statuscode int
	Length     int
}

func FingerScan(url string, flags bool) {
	FingerresultFilePath := Readyaml("Finger.resultFilePath")
	Fingerfile := Readyaml("Finger.Fingerfile")
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}
	fingerScan, err := os.OpenFile("log/fingerScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	com := "python Finger.py -u " + url
	cmd := exec.Command("cmd", "/c", com)
	cmd.Dir = Fingerfile
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err, stderr.String())
	}

	cmd.Wait()
	timeStr := time.Now().Format("20060102150405")
	resultFilePath := FingerresultFilePath + timeStr + ".xlsx"
	resultfile, err := os.Stat(resultFilePath)
	if err == nil && resultfile.Size() > 0 {
		csvlens := ReadxlsxResult(resultFilePath)
		finger := fingetiden{
			Url:     csvlens[0],
			Title:   csvlens[1],
			Cms:     csvlens[2],
			Server:  csvlens[3],
			Status:  csvlens[4],
			Size:    csvlens[5],
			Ip:      csvlens[6],
			Iscdn:   csvlens[7],
			Address: csvlens[8],
			Isp:     csvlens[9],
		}
		color.Green("%s  %s  %s  %s %s", csvlens[0], csvlens[1], csvlens[2], csvlens[3], csvlens[4])
		//fmt.Println(finger.Url, finger.Title)
		if flags {
			updateTask("Cms", finger.Cms, finger.Url)
		}

		log.SetOutput(fingerScan)
	}
}

func EHolescan(url, path string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered:", r)
		}
	}()
	EHoleresultFilePath := Readyaml("EHole.resultFilePath")
	//EHolefile := Readyaml("EHole.EHoleexe")
	//只有域名的话，添加协议
	if !strings.Contains(url, "http") {
		url = "http://" + url
	}
	fingerScan, err := os.OpenFile("log/fingerScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	now := time.Now()
	currentData := now.Format("2006-01-02")

	_, host := Urlchange(url)
	host = strings.Replace(host, ":", "-", 1)
	host = strings.Replace(host, ".", "-", -1)
	/*
		com := fmt.Sprintf("EHole finger -u %s -o result\\%s-%s.json", url, currentData, host)
		cmd := exec.Command("cmd", "/C", com)
		cmd.Dir = EHolefile
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err = cmd.Run()
		flags := cmd.Wait()
		if flags == nil {
			fmt.Println("EHole运行结束")
		}


	*/
	resultFilePath := EHoleresultFilePath + currentData + "-" + host + ".json"
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		resutl := GetEHoleresult(resultFilePath)
		color.Green("%s      %s     %s      %s     %v    %v", resutl["url"], resutl["title"], resutl["cms"], resutl["server"], resutl["statuscode"], resutl["length"])
		if path != "" {
			resutls := fmt.Sprintf("%s           %s     %s     %s    %v    %v        \r\n", resutl["url"], resutl["title"], resutl["cms"], resutl["server"], resutl["statuscode"], resutl["length"])
			savetxt(resutls, path)
		}

	}
	log.SetOutput(fingerScan)

}

func GetEHoleresult(path string) map[string]interface{} {
	filePtr, err := os.Open(path)
	if err != nil {
		fmt.Println("文件打开失败 [Err:%s]", err.Error())
	}
	defer filePtr.Close()
	var info []Website
	//使用接口类型同时返回string跟int数据
	Eholejson := make(map[string]interface{})
	// 创建json解码器
	decoder := json.NewDecoder(filePtr)
	err = decoder.Decode(&info)
	Eholejson["url"] = info[0].Url
	Eholejson["title"] = info[0].Title
	Eholejson["cms"] = info[0].Cms
	Eholejson["server"] = info[0].Server
	Eholejson["statuscode"] = info[0].Statuscode
	Eholejson["length"] = info[0].Length
	return Eholejson
}
