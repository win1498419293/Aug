package lib

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

type VulnProperties struct {
	CreateTime string
	Url        string
	Payload    string
	Vname      string
	Vabout     string
}

var (
	urls   string
	ip     string
	file   string
	mode   string
	ports  string
	thread int
	flags  bool //是否将发现的漏洞信息插入到数据库
)

func banner() {
	fmt.Println()
	num := rand.Intn(6)
	switch num {
	case 1:
		fmt.Println()
		show := "吾生也有涯，而知也无涯。以有涯随无涯，殆已！"
		banne := "                            .===;========.__,                 \n                           (\\__)___________|                 \n     L__________________,--,--/ /-,-,-\\ \\-,   ________       \n=====)o o o o ======== )) ____,===,___\"\"\" \"7_/_,_,_,_,'---,-,\n     `--._,_,_,-,--,--'' (____| _ \\___\\oo ; ; ; ; ; ;_____ T|\n              `-'--'-/_,-------| ) ___--,__,------._ \\__  |I|\n                       \\==----/   \\\\ )\\--\\_         `-._`-'I|\n                       /=[JW]/     `\"==.- -\\            `-.L|\n                      /==---/           \\- -\\                  " + show
		c := color.New(color.BlinkRapid, color.FgGreen).PrintlnFunc()
		c(banne)
	case 2:
		fmt.Println()
		show := "热血开始沸腾起来了，要上了，只狼！"
		banne := "  _____      _    _           \n / ____|    | |  (_)          \n| (___   ___| | ___ _ __ ___  \n \\___ \\ / _ \\ |/ / | '__/ _ \\ \n ____) |  __/   <| | | | (_) |\n|_____/ \\___|_|\\_\\_|_|  \\___/ \n                              \n                              " + show
		c := color.New(color.BlinkRapid, color.FgYellow).PrintlnFunc()
		c(banne)
		fmt.Println()
	case 3:
		fmt.Println()
		show := "为弱者而挥刀！"

		banne := "  ..           ..  ..                    ...    \n    ....        .........                .....    \n    ....     ................          .......    \n    .........................................     \n    .........................................     \n     ..................................... ..     \n       .................................. .       \n      .................. .................        \n       .... ..........     ...............        \n        ...  .......... ....  ..........          \n         ..  ..           .. .. .......           \n          ..                .     ...             \n           .........................              \n           ............   .........               \n             ...................                  \n              .......  ......  .                  \n                ....  .....  .                    " + show
		c := color.New(color.BlinkRapid, color.FgCyan).PrintlnFunc()
		c(banne)
		fmt.Println()
	case 4:
		fmt.Println()
		show := "疾风亦有归途，愿艾欧尼亚之灵指引你"

		banne := "                                                    \n               .                 ..               \n              ...                 ..            . \n  .           ...                ...           .. \n   ..         ....            ......        ..... \n    .......   .......         ......  ..........  \n     ..........   .. ..   . ...    ...........    \n       ...........     . .      ...........       \n        ............    ..   .............        \n        ................  ................        \n        ..................................        \n        ..................................        \n        ........................ .........        \n         ...........................  ....        \n         ...  ....................   .....        \n         .      ................    .   .         \n          .      ..............         .         \n          .           .....                       \n          .           ....                        \n                       ...                        \n                        .                         \n                                             " + show
		c := color.New(color.BlinkRapid, color.FgWhite).PrintlnFunc()
		c(banne)
		fmt.Println()
	default:
		fmt.Println()
		show := "吾儿王腾有大帝之资！"

		banne := " _________________\n< Hi, 我是牛哥。。 >\n -----------------\n        \\   ^__^\n         \\  (oo)\\_______\n            (__)\\       )\\/\\\n                ||----w |\n                ||     ||                                 " + show
		c := color.New(color.BlinkRapid, color.FgMagenta).PrintlnFunc()
		c(banne)
		fmt.Println()
	}

}

func AllScan(target, url string, thread int) {
	flags = true
	txt := ""
	domain := ""
	OneForAllresultFilePath := Readyaml("OneForAll.resultFilePath")
	if target != "" {
		txts := Readfile(target)
		// 读取全部返回的urls，判断没有协议就加上协议
		for i := 0; i < len(txts)-1; i++ {
			txt = txts[i]
			//fmt.Println(txts[i])
			if strings.Contains(txt, "http") {
				domain, _ = Urlchange(txt)
			} else {
				txt = "http://" + txt
				domain, _ = Urlchange(txt)
			}

			//收集子域名
			Collect_Subdomain_un(domain)
			fmt.Println("收集子域名")

			//创建数据表
			Connentdb()

			//读取子域名扫描结果
			SubdomainResultCsvPath := OneForAllresultFilePath + domain + ".csv"

			csvlens := ReadSubdomainResult(SubdomainResultCsvPath)
			for i := 2; i < len(csvlens)-1; i++ {
				properties := SubdomainNameProperties{
					//Id:        csvlens[i][0],
					Url:       csvlens[i][4],
					Subdomain: csvlens[i][5],
					Ip:        csvlens[i][8],
					Port:      csvlens[i][11],
					Status:    csvlens[i][12],
					Title:     csvlens[i][14],
				}
				//将内容插入子域名表
				properties.InsertTables()
				fmt.Println("插入子域名表")
			}
		}
		scan(thread)
	} else {
		if strings.Contains(url, "http") {
			domain, _ = Urlchange(url)
		} else {
			txt = "http://" + url
			domain, _ = Urlchange(txt)
		}
		//fmt.Println(domain)

		//收集子域名
		fmt.Println("收集子域名")
		Collect_Subdomain_un(domain)

		Connentdb()
		SubdomainResultCsvPath := OneForAllresultFilePath + domain + ".csv"
		fmt.Println(SubdomainResultCsvPath)

		csvlens := ReadSubdomainResult(SubdomainResultCsvPath)
		for i := 2; i < len(csvlens)-1; i++ {
			properties := SubdomainNameProperties{
				//Id:        csvlens[i][0],
				Url:       csvlens[i][4],
				Subdomain: csvlens[i][5],
				Ip:        csvlens[i][8],
				Port:      csvlens[i][11],
				Status:    csvlens[i][12],
				Title:     csvlens[i][14],
			}
			fmt.Println("插入数据库")
			properties.InsertTables()
		}
	}
	scan(thread)
}

func scan(thread int) {
	Connentdb()
	//cdn,waf检测

	checkcdn, checkwaf := SelectSubdmaindb()
	fmt.Println("waf检测")
	for id, flag := range checkwaf {
		updateSubdomain("Waf", flag, id)
		fmt.Println("cdn", flag, id)
	}
	fmt.Println("cdn检测")
	for id, flag := range checkcdn {
		updateSubdomain("Cdn", flag, id)
		fmt.Println("waf", flag, id)
	}

	//端口扫描结果创建Task表
	TableResultMap := SelectAllSubdmaindb("Cdn", "False")
	fmt.Println("端口扫描")
	for _, value := range TableResultMap {
		fmt.Println(value["ip"])
		IpScan(value["ip"], ports, flags)
	}

	//查询Task表进行指纹识别并获取cms字段写入Task表
	TaskResultMap := SelectAllTaskdb("Service", "http")
	for _, value := range TaskResultMap {
		color.Cyan("开始指纹识别")
		FingerScan(value["url"])
		color.Cyan("指纹识别结束")
		color.Yellow("开始vulmap扫描")
		vulmapscan(value["url"], thread, flags)
		color.Yellow("vulmap扫描结束")
		color.Red("开始nuclei扫描")
		nucleiscan(value["url"], flags)
		color.Red("nuclei扫描结束")
		color.White("开始pocbomber扫描")
		pocbomberscan(value["url"], thread, flags)
		color.White("pocbomber扫描结束")
	}

	//获取js敏感信息进行爬虫被动扫描漏洞
	xrayreport := ""
	fmt.Println("获取js敏感信息")
	for _, value := range TaskResultMap {
		JsSensitiveData := finderjs(value["url"])
		for i := 0; i < len(JsSensitiveData); i++ {
			xrayresult := startCrawlerGo(JsSensitiveData[i], thread)
			if xrayresult != "" {
				xrayreport = xrayresult
			}
			katanascan(JsSensitiveData[i])
		}
	}
	//判断扫描报告是否生成
	resultfile, err := os.Stat(xrayreport)
	if err == nil && resultfile.Size() > 0 {
		fmt.Println("读取扫描报告")
		fmt.Println(xrayreport)

		//获取扫描的漏洞信息保存到漏洞表
		ghr := GetXrayHtmlResult(xrayreport)
		for _, vaule := range ghr {
			if vaule["addr"] != "" {
				properties := VulnProperties{
					CreateTime: vaule["createTi"],
					Url:        vaule["target"],
					Payload:    vaule["Paylo"],
					Vname:      vaule["plugin"],
					Vabout:     vaule["addr"],
				}
				fmt.Println("漏洞插入数据库")
				properties.InsertVulTables()
			}
		}
	}
	log.Println("漏洞扫描完成")

}

func scanmode() {
	c := color.New()
	c.Add(color.FgHiGreen, color.Bold)
	banner()
	flag.Parse()
	switch mode {
	case "f":
		start := time.Now() // 获取当前时间
		txts := Readfile(file)
		// 读取全部返回的urls，判断没有协议就加上协议
		for i := 0; i < len(txts); i++ {
			url := txts[i]
			c.Printf("%s开始扫描:", url)
			fmt.Println()
			JsSensitiveData := finderjs(url)
			katanascan(url)
			for i := 0; i < len(JsSensitiveData); i++ {
				startCrawlerGo(JsSensitiveData[i], thread)
			}
			c.Printf("%s扫描完成", url)

		}
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "all":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始扫描:", urls)
		fmt.Println()
		if file == "" {
			AllScan("", urls, thread)
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				AllScan(file, "", thread)
			}
		}
		c.Printf("%s扫描完成", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "ps":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始端口扫描%s: ", ip, ports)
		fmt.Println()
		IpScan(ip, ports, flags)
		c.Printf("%s端口扫描完成 ", ip)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "vs":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始漏洞扫描: ", urls)
		fmt.Println()
		if file == "" {
			color.Cyan("开始指纹识别")
			FingerScan(urls)
			color.Cyan("指纹识别结束")
			color.Yellow("开始vulmap扫描")
			vulmapscan(urls, thread, flags)
			color.Yellow("vulmap扫描结束")
			color.Red("开始nuclei扫描")
			nucleiscan(urls, flags)
			color.Red("nuclei扫描结束")
			color.White("开始pocbomber扫描")
			pocbomberscan(urls, thread, flags)
			color.White("pocbomber扫描结束")
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				color.Cyan("%s:开始指纹识别", txts[i])
				FingerScan(txts[i])
				color.Cyan("%s:指纹识别结束", txts[i])
				color.Yellow("%s:开始vulmap扫描", txts[i])
				vulmapscan(txts[i], thread, flags)
				color.Yellow("%s:vulmap扫描结束", txts[i])
				color.Red("%s:开始nuclei扫描", txts[i])
				nucleiscan(txts[i], flags)
				color.Red("%s:nuclei扫描结束", txts[i])
				color.White("%s:开始pocbomber扫描", txts[i])
				pocbomberscan(txts[i], thread, flags)
				color.White("%s:pocbomber扫描结束", txts[i])
			}
		}

		c.Printf("%s漏洞扫描完成 ", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "sf":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始备份文件扫描: ", urls)
		fmt.Println()
		if file == "" {
			backfilescan(urls, thread)
			dirsearchscan(urls, thread)
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				backfilescan(txts[i], thread)
				dirsearchscan(txts[i], thread)
			}
		}

		c.Printf("%s备份文件扫描完成: ", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "ds":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始目录扫描: ", urls)
		fmt.Println()
		if file == "" {
			dirsearchscan(urls, thread)
		} else {
			txts := Readfile(file)
			for i := 0; i < len(txts); i++ {
				fmt.Println("开始扫描:", txts[i])
				dirsearchscan(txts[i], thread)
			}
		}
		c.Printf("%s目录扫描完成: ", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始单url扫描: ", urls)
		fmt.Println()
		if file == "" {
			JsSensitiveData := finderjs(urls)
			katanascan(urls)
			for i := 0; i < len(JsSensitiveData); i++ {
				xrayresult := startCrawlerGo(JsSensitiveData[i], thread)
				resultfile, err := os.Stat(xrayresult)
				if xrayresult != "" && err == nil && resultfile.Size() > 0 {
					ghr := GetXrayHtmlResult(xrayresult)
					for _, vaule := range ghr {
						if vaule["addr"] != "" {
							c.Println(vaule["createTi"], vaule["target"], vaule["plugin"])
						}
					}
				}
			}
			color.Magenta("开始目录扫描")
			dirsearchscan(urls, thread)
			color.Magenta("目录扫描结束")
			color.Cyan("开始指纹识别")
			FingerScan(urls)
			color.Cyan("指纹识别结束")
			color.Yellow("开始vulmap扫描")
			vulmapscan(urls, thread, flags)
			color.Yellow("vulmap扫描结束")
			color.Red("开始nuclei扫描")
			nucleiscan(urls, flags)
			color.Red("nuclei扫描结束")
			color.White("开始pocbomber扫描")
			pocbomberscan(urls, thread, flags)
			color.White("pocbomber扫描结束")
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				JsSensitiveData := finderjs(txts[i])
				katanascan(txts[i])
				for i := 0; i < len(JsSensitiveData); i++ {
					startCrawlerGo(JsSensitiveData[i], thread)
				}
			}
		}
		c.Printf("%s扫描完成: ", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "rh":
		c.Printf("请访问本机9999/端口查看漏洞数据: ")
		fmt.Println()
		runhtml()
	case "clear":
		SelectPath(".json")
		SelectPath(".html")
		SelectPath(".txt")
		SelectPath(".csv")
		SelectPath(".xlsx")
		color.Blue("扫描文件清理成功")
	default:
		color.Red("输入有误请检查参数下面是详情:%s", mode)
	}
}
func Startmain() {
	scanmode()
	//pocbomberscan("http://36.155.98.9:27071/privatemanage/", 10, false)

}

func init() {
	//是否保存扫描发现的漏洞到数据库
	flag.BoolVar(&flags, "s", false, "save,是否将扫描发现的问题保存到数据库里")
	//只扫描一个站点url
	flag.StringVar(&urls, "u", "", "url，待扫描的url")
	//线程数量
	flag.IntVar(&thread, "t", 50, "thread，输入线程数量。默认50")
	//多url扫描
	flag.StringVar(&file, "f", "", "file，读取文件内容进行扫描")
	//端口扫描
	flag.StringVar(&ip, "i", "", "ip，扫描端口情况，需配合-p 使用")
	//端口范围
	flag.StringVar(&ports, "p", "-t1000", "ports，需要扫描的端口或端口范围,如-p 1-100，-p 100")
	//模式选择：默认单站点扫描  all多全流程扫描 vul仅漏洞扫描
	flag.StringVar(&mode, "m", "", "扫描类型，示例 -m all全流程扫描，-m f 读取文件内容扫描,-m vs漏洞扫描,不加-m 默认为单url扫描,-m ps端口扫描，-m ds目录扫描 -m sf备份文件+目录扫描,-m rh查看任务数据, -m clear 清除扫描的结果文件")
}

// 按照类型删除报错的扫描结果文件
func SelectPath(ftype string) {
	switch {
	case ftype == ".json":
		TxPortMapresultFilePath := Readyaml("TxPortMap.resultFilePath")
		removetmp(TxPortMapresultFilePath, ftype)
		nucleiexe := Readyaml("nuclei.resultFilePath")
		removetmp(nucleiexe, ftype)
	case ftype == ".html":
		jsfinderfile := Readyaml("JSFinderPlus.resultFilePath")
		removetmp(jsfinderfile, ftype)
		xrayresultFilePath := Readyaml("xray.resultFilePath")
		fmt.Println(xrayresultFilePath)
		removetmp(xrayresultFilePath, ftype)
	case ftype == ".txt":
		katanaexe := Readyaml("katana.resultFilePath")
		removetmp(katanaexe, ftype)
		dirsearchfile := Readyaml("dirsearch.resultFilePath")
		removetmp(dirsearchfile, ftype)
		CDNcheckexe := Readyaml("CDNcheck.resultFilePath")
		removetmp(CDNcheckexe, ftype)

		pocbomberfile := Readyaml("POC_bomber.resultFilePath")
		removetmp(pocbomberfile, ftype)
	case ftype == ".csv":
		OneForAllresultFilePath := Readyaml("OneForAll.resultFilePath")
		fmt.Println(OneForAllresultFilePath)
		removetmp(OneForAllresultFilePath, ftype)
	case ftype == ".xlsx":
		Fingerfile := Readyaml("Finger.resultFilePath")
		removetmp(Fingerfile, ftype)
	}

}

// 删除扫描完成后输出的扫描结果文件
func removetmp(path, ftype string) {
	files, err := ioutil.ReadDir(path) // 替换成你的目录路径
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	for _, refile := range files {
		//判断是否包含指定文件后辍名，安装文件类型删除
		if strings.Contains(refile.Name(), ftype) {
			err := os.Remove(path + refile.Name())
			if err != nil {
				fmt.Println(err)
			}
			color.Magenta("删除" + path + refile.Name() + "成功")
		}

	}
}
