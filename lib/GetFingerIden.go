package lib

import (
	"bytes"
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

func FingerScan(url string) {
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

	flags := cmd.Wait()

	if flags == nil {
		log.Println("运行结束")
	}
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
		updateTask("Cms", finger.Cms, finger.Url)
		log.SetOutput(fingerScan)
	}
}
