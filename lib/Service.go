package lib

import (
	"bytes"
	"context"
	"fmt"
	"github.com/chromedp/chromedp"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
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

// c段扫描
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

// web页面截图
func Webscreenshot(url string) {
	// 创建上下文
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	// 设置超时时间
	timeout := 10 * time.Second // 设置为您期望的超时时间

	// 创建带有超时的上下文
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()
	// 设置浏览器选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("remote-debugging-timeout", "10s"), // 增加超时时间为300秒（默认是2分钟）
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// 创建浏览器实例
	ctx, cancel = chromedp.NewContext(allocCtx)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		log.Fatal(err)
	}

	// 等待页面加载完成
	if err := chromedp.Run(ctx, chromedp.WaitVisible("body")); err != nil {
		log.Fatal(err)
	}

	// 获取页面的宽度和高度
	width := 1920
	height := 1080
	if err := chromedp.Run(ctx, chromedp.Evaluate(`() => {
        return {
            width: document.documentElement.clientWidth,
            height: document.documentElement.clientHeight
        };
    }`, &map[string]int{
		"width":  width,
		"height": height,
	})); err != nil {
		log.Fatal(err)
	}

	// 设置视口大小
	if err := chromedp.Run(ctx, chromedp.EmulateViewport(int64(width), int64(height))); err != nil {
		log.Fatal(err)
	}
	time.Sleep(1)
	// 获取页面截图
	var buf []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&buf)); err != nil {
		log.Fatal(err)
	}

	shotname, _ := Urlchange(url)
	// 将截图保存到文件
	if err := saveScreenshot("screenshot/"+shotname+".png", buf); err != nil {
		log.Fatal(err)
	}
}

func saveScreenshot(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)

}
