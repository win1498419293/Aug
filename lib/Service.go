package lib

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

func IsIPAlive(ip string, wg *sync.WaitGroup) {
	defer wg.Done()
	cmd := exec.Command("cmd", "/c", "ping -a -n 1 "+ip)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	if strings.Contains(out.String(), "TTL=") {
		fmt.Println(ip)
		//IpScan(false, ip, src, "-t1000", "")
	}
}
func cscan(ip string) {
	num := strings.LastIndex(ip, ".")
	newip := ip[0:num]
	var wg sync.WaitGroup
	for i := 0; i < 255; i++ {
		wg.Add(1)
		go IsIPAlive(newip+"."+strconv.Itoa(i), &wg)
	}
	wg.Wait()

}
