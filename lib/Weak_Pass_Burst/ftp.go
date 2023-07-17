package Weak_Pass_Burst

import (
	"fmt"
	"github.com/dutchcoders/goftp"
	"sync"
)

func FtpAuth(target, port, user, pass string) (result bool, err error) {
	result = false
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("panic occurred: %v", r)
		}
	}()
	ftpauto, err := goftp.Connect(target + ":" + port)
	if err != nil {
		fmt.Println(err, "连接出现错误")
	}
	err = ftpauto.Login(user, pass)
	if err != nil {
		fmt.Println(err, "登录失败")
	} else {
		result = true
	}
	return result, err
}

func FtpScan(ScanType string, Target string) {
	user := Readfile("dic/dic_username_ftp.txt")
	pass := Readfile("dic/dic_password_ftp.txt")

	resultChan := make(chan string)

	var wg sync.WaitGroup
	for _, u := range user {
		for _, p := range pass {
			wg.Add(1)
			go func(u, p string) {
				defer wg.Done()
				fmt.Println("Check... " + Target + " " + u + " " + p)
				res, err := FtpAuth(Target, "21", u, p)
				if res && err == nil {
					resultChan <- fmt.Sprintf("%s %s 3306 %s %s", ScanType, Target, u, p)
				} else if err != nil {
					resultChan <- fmt.Sprintf("Error occurred: %v", err)
				}
			}(u, p)
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

}
