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

func FingerScan(flags bool, params ...string) {
	FingerresultFilePath := Readyaml("Finger.resultFilePath")
	Fingerfile := Readyaml("Finger.Fingerfile")
	url := params[0]
	paths := ""
	if len(params) > 1 {
		paths = params[1]
	}

	isfiles := isfile(url)

	com := ""
	if isfiles {
		com = "python Finger.py -f " + url
	} else {
		//只有域名的话，添加协议
		if !strings.Contains(url, "http") {
			url = "http://" + url
		}
		com = "python Finger.py -u " + url

	}

	fingerScan, err := os.OpenFile("log/fingerScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
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
		for i := 0; i < len(csvlens); i += 10 {
			color.Green("%s  %s  %s  %s %s", csvlens[i+0], csvlens[i+1], csvlens[i+2], csvlens[i+3], csvlens[i+4])
			results := fmt.Sprintf("%s  %s %s %s  %s \r\n ", csvlens[i+0], csvlens[i+1], csvlens[i+2], csvlens[i+3], csvlens[i+4])
			if paths != "" {
				savetxt(results, paths)
			}
		}
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
	fingerScan, err := os.OpenFile("log/fingerScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	now := time.Now()
	currentData := now.Format("2006-01-02")
	EHoleresultFilePath := Readyaml("EHole.resultFilePath")
	EHolefile := Readyaml("EHole.EHoleexe")
	isfiles := isfile(url)

	com := ""

	if isfiles {
		com = fmt.Sprintf("EHole finger -l %s -o result\\%s.json", url, currentData)
	} else {
		//只有域名的话，添加协议
		if !strings.Contains(url, "http") {
			url = "http://" + url
		}
		_, host := Urlchange(url)
		host = strings.Replace(host, ":", "-", 1)
		host = strings.Replace(host, ".", "-", -1)
		com = fmt.Sprintf("EHole finger -u %s -o result\\%s-%s.json", url, currentData, host)
	}

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

	resultFilePath := ""
	if isfiles {
		resultFilePath = EHoleresultFilePath + currentData + ".json"
	} else {
		_, host := Urlchange(url)
		host = strings.Replace(host, ":", "-", 1)
		host = strings.Replace(host, ".", "-", -1)
		resultFilePath = EHoleresultFilePath + currentData + "-" + host + ".json"
	}
	resultFile, err := os.Stat(resultFilePath)
	if err == nil && resultFile.Size() > 0 {
		resutl := GetEHoleresult(resultFilePath)
		for i := 0; i < len(resutl); i++ {
			color.Green("%s      %s     %s      %s     %v    %v", resutl[i]["url"], resutl[i]["title"], resutl[i]["cms"], resutl[i]["server"], resutl[i]["statuscode"], resutl[i]["length"])
			if path != "" {
				resutls := fmt.Sprintf("%s           %s     %s     %s    %v    %v        \r\n", resutl[i]["url"], resutl[i]["title"], resutl[i]["cms"], resutl[i]["server"], resutl[i]["statuscode"], resutl[i]["length"])
				savetxt(resutls, path)
			}
		}

	}
	log.SetOutput(fingerScan)

}

func GetEHoleresult(path string) map[int]map[string]interface{} {
	filePtr, err := os.Open(path)
	if err != nil {
		fmt.Println("文件打开失败 [Err:%s]", err.Error())
	}
	defer filePtr.Close()
	var info []Website
	//使用接口类型同时返回string跟int数据
	Eholejson := make(map[int]map[string]interface{})
	// 创建json解码器
	decoder := json.NewDecoder(filePtr)
	err = decoder.Decode(&info)
	for i := 0; i < len(info); i++ {
		Eholejson[i] = make(map[string]interface{})
		Eholejson[i]["url"] = info[i].Url
		Eholejson[i]["title"] = info[i].Title
		Eholejson[i]["cms"] = info[i].Cms
		Eholejson[i]["server"] = info[i].Server
		Eholejson[i]["statuscode"] = info[i].Statuscode
		Eholejson[i]["length"] = info[i].Length
	}

	return Eholejson
}

func isfile(url string) bool {
	isfile, err := os.Stat(url)
	if err != nil {
		return false
	}
	if isfile.Mode().IsRegular() {
		return true
	}
	return false
}
