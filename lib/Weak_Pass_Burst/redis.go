package Weak_Pass_Burst

import (
	"fmt"
	"github.com/go-redis/redis"
	"strconv"
	"sync"
	"time"
)

func RedisNullAuth(host string, iport int) (err error, result bool) {
	portt := strconv.Itoa(iport)
	opt := redis.Options{Addr: fmt.Sprintf("%v:%v", host, portt),
		Password: "", DB: 0, DialTimeout: 2 * time.Second}
	client := redis.NewClient(&opt)
	_, err = client.Ping().Result()
	defer client.Close()
	if err == nil {
		fmt.Println("Redis 服务存在空口令 " + host + ":" + fmt.Sprintln(iport))
		result = true
	}
	return err, result
}
func RedisAuth(host, password string, iport int) (result bool, err error) {
	portt := strconv.Itoa(iport)
	opt := redis.Options{Addr: fmt.Sprintf("%v:%v", host, portt),
		Password: password, DB: 0, DialTimeout: 5 * time.Second}
	client := redis.NewClient(&opt)
	_, err = client.Ping().Result()
	client.Close()
	if err == nil {
		fmt.Println("Redis 服务存在弱口令 " + host + ":" + fmt.Sprintln(iport))
		result = true
	}
	return result, err
}

func RedisScan(ScanType string, ip string) {
	pass := Readfile("dic/dic_password_redis.txt")

	resultChan := make(chan string)

	var wg sync.WaitGroup
	for _, p := range pass {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			fmt.Println("Check... " + ip + ": 6379" + " " + p)
			res, err := RedisAuth(ip, p, 6379)
			if res && err == nil {
				resultChan <- fmt.Sprintf("%s %s 6379 %s", ScanType, ip, p)
			} else if err != nil {
				resultChan <- fmt.Sprintf("Error occurred: %v", err)
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

}
