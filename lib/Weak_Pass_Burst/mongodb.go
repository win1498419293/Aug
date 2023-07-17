package Weak_Pass_Burst

import (
	"fmt"
	"gopkg.in/mgo.v2"
	"sync"
	"time"
)

func MongodbAuth(user, pass, ip, port string) (result bool, err error) {
	result = false
	session, err := mgo.DialWithTimeout("mongodb://"+user+":"+pass+"@"+ip+":"+port+"/"+"admin", time.Second*3)
	if err == nil && session.Ping() == nil {
		defer session.Close()
		if err == nil && session.Run("serverStatus", nil) == nil {
			result = true
		}
	}
	return result, err
}

func MongoUnAuth(ip string, port string) (result bool, err error) {
	result = false
	session, err := mgo.Dial(ip + ":" + port)
	if err == nil && session.Run("serverStatus", nil) == nil {
		result = true
	}
	return result, err
}

func MongodbScan(ScanType string, ip string) {
	user := Readfile("dic/dic_username_mongodb.txt")
	pass := Readfile("dic/dic_password_mongodb.txt")

	resultChan := make(chan string)

	var wg sync.WaitGroup
	for _, u := range user {
		for _, p := range pass {
			wg.Add(1)
			go func(u, p string) {
				defer wg.Done()
				fmt.Println("Check... " + ip + " " + u + " " + p)
				res, err := MongodbAuth(ip, "27017", u, p)
				if res && err == nil {
					resultChan <- fmt.Sprintf("%s %s 27017 %s %s", ScanType, ip, u, p)

					return
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
