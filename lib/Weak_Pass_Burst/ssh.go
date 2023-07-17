package Weak_Pass_Burst

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"strings"
)

/*
func SshAuth(ip, port, user, pass string) (result bool, err error) {
	result = false

	config := &ssh.ClientConfig{
		Timeout:         time.Second * 3,
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //这个可以， 但是不够安全
		//HostKeyCallback: hostKeyCallBackFunc(h.Host),
	}
	config.Ciphers = append(config.Ciphers, "aes128-ctr")
	config.Auth = []ssh.AuthMethod{ssh.Password(pass)}

	//dial 获取ssh client
	addr := fmt.Sprintf("%s:%s", ip, port)
	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatal("创建ssh client 失败", err)
	}
	defer sshClient.Close()
	//创建ssh-session
	session, err := sshClient.NewSession()
	if err != nil {
		log.Fatal("创建ssh session 失败", err)
	}
	defer session.Close()
	//执行远程命令
	combo, err := session.CombinedOutput("ls -lh")
	if err != nil {
		log.Fatal("远程执行cmd 失败", err)
	}
	log.Println("命令输出:", string(combo))
	fmt.Println("命令输出:", string(combo))

	return result, err
}

*/

func SshScan(ScanType string, ip string) {
	SshScanlog, err := os.OpenFile("log/sshscan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	log.SetOutput(SshScanlog) // 将文件设置为log输出的文件
	log.SetPrefix("[log]")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	usernames := Readfile("dic/dic_username_ssh.txt")
	passwords := Readfile("dic/dic_password_ssh.txt")
	/*
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

					fmt.Println("Check... " + ScanType + ip + " " + u + " " + p)
					log.Println("Check... " + ip + " " + u + " " + p)
					res, err := SshAuth(ip, "22", u, p)

					if res && err == nil {
						// 使用 sync.Once 来确保只执行一次
						once.Do(func() {
							success = true
							log.Println(ip + " " + u + " " + p)
							close(resultChan) // 关闭 resultChan 以终止其他 goroutine
						})
						resultChan <- fmt.Sprintf("%s %s 22 %s %s", ScanType, ip, u, p)
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

	*/
	for _, u := range usernames {
		for _, p := range passwords {
			newp := strings.Replace(p, "%user%", u, 1)
			fmt.Println("Check... " + ScanType + ip + " " + u + " " + newp)
			res, err := SshAuth(ip, "22", u, newp)
			if res && err == nil {
				fmt.Println("11")
			}

		}
	}
}

func SshAuth(host string, port string, user string, pass string) (result bool, err error) {
	result = false

	authMethods := []ssh.AuthMethod{}

	keyboardInteractiveChallenge := func(
		user,
		instruction string,
		questions []string,
		echos []bool,
	) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{pass}, nil
	}

	authMethods = append(authMethods, ssh.KeyboardInteractive(keyboardInteractiveChallenge))
	authMethods = append(authMethods, ssh.Password(pass))

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
		//HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", host, port), sshConfig)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo ISOK")
		if err == nil && errRet == nil {
			defer session.Close()
			result = true
		}
	}
	return result, err
}
