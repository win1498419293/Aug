package Weak_Pass_Burst

import (
	"fmt"
	"github.com/stacktitan/smb/smb"
	"log"
	"sync"
)

func SmbAuth(ip, user, pass string) (result bool, err error) {
	result = false
	options := smb.Options{
		Host:        ip,
		Port:        445,
		User:        user,
		Domain:      "",
		Workstation: "",
		Password:    pass,
	}
	debug := false
	session, err := smb.NewSession(options, debug)
	if err != nil {
		log.Fatalln("[!]", err)
	}
	defer session.Close()

	if session.IsSigningRequired {
		log.Println("[-] Signing is required")
	} else {
		log.Println("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Println("[+] Login successful")
		result = true
	} else {
		log.Println("[-] Login failed")
	}
	return result, err
}

func SmbScan(ScanType string, ip string) {
	user := Readfile("dic/dic_username_smb.txt")
	pass := Readfile("dic/dic_password_smb.txt")

	resultChan := make(chan string)

	var wg sync.WaitGroup
	for _, u := range user {
		for _, p := range pass {
			wg.Add(1)
			go func(u, p string) {
				defer wg.Done()
				fmt.Println("Check... " + ip + " " + u + " " + p)
				res, err := SmbAuth(ip, u, p)
				if res && err == nil {
					resultChan <- fmt.Sprintf("%s %s 445 %s %s", ScanType, ip, u, p)
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
