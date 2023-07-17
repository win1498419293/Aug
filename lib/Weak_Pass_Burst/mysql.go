package Weak_Pass_Burst

import (
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
	"sync"
	"time"
)

// 读取文件返回内容, scanner.Scan()没法读取全部html文件
func Readfile(path string) []string {

	//var enc mahonia.Decoder
	//enc = mahonia.NewDecoder("gbk")
	txt := []string{}
	//创建日志
	logfile, err := os.OpenFile("log/readfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	//写入日志

	defer file.Close()
	scanner := bufio.NewScanner(file) // 类似Java中的Scanner
	for scanner.Scan() {
		txt = append(txt, scanner.Text())

	}
	log.SetOutput(logfile)
	return txt

}

var once sync.Once
var success bool // 声明一个变量用于记录成功状态

func MysqlScan(ScanType string, ip string) {
	MysqlScanlog, err := os.OpenFile("log/MysqlScan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	log.SetOutput(MysqlScanlog) // 将文件设置为log输出的文件
	log.SetPrefix("[log]")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	usernames := Readfile("dic/dic_username_mysql.txt")
	passwords := Readfile("dic/dic_password_mysql.txt")

	// 设置并发限制
	concurrencyLimit := 10 // 限制并发数量
	semaphore := make(chan struct{}, concurrencyLimit)

	resultChan := make(chan string)
	var wg sync.WaitGroup
	for _, u := range usernames {
		for _, p := range passwords {
			wg.Add(1)
			semaphore <- struct{}{} // 占用一个并发槽

			go func(u, p string) {
				defer func() {
					<-semaphore // 释放并发槽
					wg.Done()
				}()

				fmt.Println("Check... " + ip + " " + u + " " + p)
				log.Println("Check... " + ip + " " + u + " " + p)
				res, err := MysqlAuth(ip, "3306", u, p)

				if res && err == nil {
					// 使用 sync.Once 来确保只执行一次
					once.Do(func() {
						success = true
						log.Println(ip + " " + u + " " + p)
						close(resultChan) // 关闭 resultChan 以终止其他 goroutine
					})
					resultChan <- fmt.Sprintf("%s %s 3306 %s %s", ScanType, ip, u, p)
				} else if err != nil {
					resultChan <- fmt.Sprintf("Error occurred for %s %s: %v", u, p, err)
				}
			}(u, p)

			// 如果已经成功，退出循环
			if success {
				break
			}
		}

		// 如果已经成功，退出循环
		if success {
			break
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 处理结果
	for result := range resultChan {
		// 在这里处理结果，例如将结果写入文件或进行其他操作
		fmt.Println(result)
		log.Println(result)

	}
	log.SetOutput(MysqlScanlog)
}

func MysqlAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("panic occurred: %v", r)
		}
	}()
	db, err := sql.Open("mysql", user+":"+pass+"@tcp("+ip+":"+port+")/mysql?charset=utf8")
	db.SetConnMaxLifetime(5 * time.Second)
	if err != nil {
		panic(err)
	}
	if db.Ping() == nil {
		result = true
	}
	return result, err
}
