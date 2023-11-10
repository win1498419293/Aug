package lib

import (
	"Aug/lib/Weak_Pass_Burst"
	//"Aug/web"
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
	Src        string
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
	src    string
	output string
)

func banner() {
	fmt.Println()
	num := rand.Intn(10)
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
	case 5:
		fmt.Println()
		show := "  相信我"

		banne := " ____                         _______                        ______ ___ ______ _  _   \n |  _ \\                       |__   __|                      |____  |__ \\____  | || |  \n | |_) |_ __ __ ___   _____      | | __ _ _ __   __ _  ___       / /   ) |  / /| || |_ \n |  _ <| '__/ _` \\ \\ / / _ \\     | |/ _` | '_ \\ / _` |/ _ \\     / /   / /  / / |__   _|\n | |_) | | | (_| |\\ V / (_) |    | | (_| | | | | (_| | (_) |   / /   / /_ / /     | |  \n |____/|_|  \\__,_| \\_/ \\___/     |_|\\__,_|_| |_|\\__, |\\___/   /_/   |____/_/      |_|  \n                                                 __/ |                                 \n                                                |___/                                  " + show
		c := color.New(color.BlinkRapid, color.FgWhite).PrintlnFunc()
		c(banne)
		fmt.Println()

	case 6:
		fmt.Println()
		show := "相信我"

		banne := " ____                         _______                        ______ ___ ______ _  _   \n |  _ \\                       |__   __|                      |____  |__ \\____  | || |  \n | |_) |_ __ __ ___   _____      | | __ _ _ __   __ _  ___       / /   ) |  / /| || |_ \n |  _ <| '__/ _` \\ \\ / / _ \\     | |/ _` | '_ \\ / _` |/ _ \\     / /   / /  / / |__   _|\n | |_) | | | (_| |\\ V / (_) |    | | (_| | | | | (_| | (_) |   / /   / /_ / /     | |  \n |____/|_|  \\__,_| \\_/ \\___/     |_|\\__,_|_| |_|\\__, |\\___/   /_/   |____/_/      |_|  \n                                                 __/ |                                 \n                                                |___/                                  " + show
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

func AllScan(target, url, src string, thread int) {
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

			fmt.Println("正在收集子域名")

			//创建数据表
			Connentdb()
			result := Subfinder(urls)
			for i := 0; i < len(result)-1; i++ {
				str := strings.Split(result[i], "")
				for k := 0; k < len(str)-1; k += 3 {
					if k+3 < len(str) {
						properties := SubdomainNameProperties{
							//Id:        csvlens[i][0],
							Src:       src,
							Url:       str[0],
							Subdomain: domain,
							Ip:        str[3],
							Status:    str[1],
							Title:     str[2],
						}
						//将内容插入子域名表
						properties.InsertTables()
						fmt.Println("插入子域名表")
					}

				}

			}
			//读取子域名扫描结果
			SubdomainResultCsvPath := OneForAllresultFilePath + domain + ".csv"

			csvlens := ReadSubdomainResult(SubdomainResultCsvPath)
			for i := 2; i < len(csvlens)-1; i++ {
				properties := SubdomainNameProperties{
					//Id:        csvlens[i][0],
					Src:       src,
					Url:       csvlens[i][4],
					Subdomain: csvlens[i][5],
					Ip:        csvlens[i][8],
					Status:    csvlens[i][12],
					Title:     csvlens[i][14],
				}
				//将内容插入子域名表
				properties.InsertTables()
				fmt.Println("插入子域名表")
			}
		}
		Scan(src, url, thread)
	} else {
		if strings.Contains(url, "http") {
			domain, _ = Urlchange(url)
		} else {
			txt = "http://" + url
			domain, _ = Urlchange(txt)
		}
		//fmt.Println(domain)

		//收集子域名
		fmt.Println("正在收集子域名")
		Collect_Subdomain_un(domain)

		Connentdb()
		result := Subfinder(urls)
		for i := 0; i < len(result)-1; i++ {
			str := strings.Split(result[i], "")
			for k := 0; k < len(str)-1; k += 3 {
				if k+3 < len(str) {
					properties := SubdomainNameProperties{
						//Id:        csvlens[i][0],
						Src:       src,
						Url:       str[0],
						Subdomain: domain,
						Ip:        str[3],
						Status:    str[1],
						Title:     str[2],
					}
					//将内容插入子域名表
					properties.InsertTables()
					fmt.Println("插入子域名表")
				}

			}

		}
		SubdomainResultCsvPath := OneForAllresultFilePath + domain + ".csv"
		//fmt.Println(SubdomainResultCsvPath)

		csvlens := ReadSubdomainResult(SubdomainResultCsvPath)
		fmt.Println("插入子域名表")
		for i := 2; i < len(csvlens)-1; i++ {
			properties := SubdomainNameProperties{
				//Id:        csvlens[i][0],
				Src:       src,
				Url:       csvlens[i][4],
				Subdomain: csvlens[i][5],
				Ip:        csvlens[i][8],
				Status:    csvlens[i][12],
				Title:     csvlens[i][14],
			}

			properties.InsertTables()
		}
	}
	Scan(src, url, thread)
}

func Scan(src, url string, thread int) {
	Connentdb()

	getsubnum := SelectAllSubdmaindb("", "", src)
	fmt.Println("本次共收集: ", len(getsubnum)+1, "个子域名")
	//cdn,waf检测
	checkcdn, checkwaf := SelectSubdmaindb(src, url)

	fmt.Println("开始waf检测")
	for id, flag := range checkwaf {
		updateSubdomain("Waf", flag, id)
	}
	fmt.Println("开始cdn检测")
	for id, flag := range checkcdn {
		updateSubdomain("Cdn", flag, id)

	}

	//端口扫描结果创建Task表
	TableResultMap := SelectAllSubdmaindb("Cdn", "False", src, url)
	fmt.Println("开始端口扫描,本次共扫描", len(TableResultMap)+1, "个ip")
	lastip := ""
	for _, value := range TableResultMap {
		if value["ip"] != lastip {
			lastip = value["ip"]
			//跳过本地地址
			if value["ip"] != "127.0.0.1" {
				IpScan(flags, value["ip"], ports, src, value["url"])
			}

		}
	}

	//查询Task表进行指纹识别并获取cms字段写入Task表
	TaskResultMap := SelectAllTaskdb("Service", "http", src, url)
	fmt.Println("本次共插入: ", len(TaskResultMap)+1, "个url至Task表")
	fmt.Println("开始漏洞扫描,本次共扫描", len(TaskResultMap)+1, "个url")
	num := len(TaskResultMap)
	sum := 1
	for _, value := range TaskResultMap {
		Webscreenshot(value["url"])
		fmt.Println("正在扫描第", sum, "个url，还有", num, "需要url扫描")
		color.Cyan("开始指纹识别")
		FingerScan(value["url"], flags)
		EHolescan(value["url"], output)
		color.Cyan("指纹识别结束")
		color.Yellow("开始vulmap扫描")
		Vulmapscan(value["url"], src, thread, flags)
		color.Yellow("vulmap扫描结束")
		color.Red("开始nuclei扫描")
		Nucleiscan(value["url"], src, flags)
		color.Red("nuclei扫描结束")
		color.White("开始pocbomber扫描")
		Pocbomberscan(value["url"], src, thread, flags)
		color.White("pocbomber扫描结束")
		color.Green("开始Find-SomeThing扫描")
		FindSomeThingscan(value["url"], src, flags)
		color.Green("Find-SomeThing扫描结束")
		sum += 1
		num -= 1
	}

	//获取js敏感信息进行爬虫被动扫描漏洞
	xrayreport := ""
	fmt.Println("开始获取js敏感信息")
	for _, value := range TaskResultMap {
		JsSensitiveData := Finderjs(value["url"])
		for i := 0; i < len(JsSensitiveData); i++ {
			xrayresult := StartCrawlerGo(JsSensitiveData[i], thread)
			if xrayresult != "" {
				xrayreport = xrayresult
			}
			Katanascan(JsSensitiveData[i])
		}
	}
	//判断扫描报告是否生成
	resultfile, err := os.Stat(xrayreport)
	if err == nil && resultfile.Size() > 0 {
		fmt.Println("开始读取扫描报告")
		fmt.Println(xrayreport)

		//获取扫描的漏洞信息保存到漏洞表
		ghr := GetXrayHtmlResult(xrayreport)
		for _, vaule := range ghr {
			if vaule["addr"] != "" {
				properties := VulnProperties{
					Src:        src,
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
	case "csub":
		start := time.Now() // 获取当前时间
		subfinderFilePath := Readyaml("Subfinder.resultFilePath")
		c.Printf("%s开始子域名收集:", urls)
		fmt.Println()
		txt := ""
		domain := ""
		properties := SubdomainNameProperties{}
		if file == "" {
			//Collect_Subdomain_un(urls)
			result := Subfinder(urls)
			for i := 0; i < len(result); i++ {
				if output != "" {
					savetxt(result[i], subfinderFilePath+output)
				} else {
					c.Printf("%s开始子域名收集:", result[i])
				}

				if flags {
					//创建数据表
					Connentdb()
					str := strings.Split(result[i], " ")
					for k := 0; k < len(str)-1; k += 3 {
						if k+3 < len(str) {
							properties = SubdomainNameProperties{
								Src:       src,
								Url:       str[0],
								Subdomain: urls,
								Ip:        str[3],
								Status:    str[1],
								Title:     str[2],
							}

						}

					}
					//将内容插入子域名表
					properties.InsertTables()
					fmt.Println("插入子域名表")
				} else {
					fmt.Println(result[i])
				}
			}
		} else {
			txts := Readfile(file)
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
				Subfinder(domain)
			}
		}
		c.Printf("%s子域名收集完成", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)

	case "fs":
		start := time.Now() // 获取当前时间
		if file == "" {
			c.Printf("%s开始指纹扫描:", urls)
			EHolescan(urls, output)
		} else {
			txts := Readfile(file)
			for i := 0; i < len(txts); i++ {
				EHolescan(txts[i], output)
			}
		}
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "all":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始扫描:", urls)
		fmt.Println()
		if file == "" {
			AllScan("", urls, src, thread)
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				AllScan(file, "", src, thread)
			}
		}
		c.Printf("%s扫描完成", urls)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "ps":
		start := time.Now() // 获取当前时间
		if file == "" {
			c.Printf("%s开始端口扫描%s: ", ip, ports)
			fmt.Println()
			IpScan(flags, ip, ports, src, output)
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				c.Printf("%s开始端口扫描%s: ", txts[i], ports)
				fmt.Println()
				IpScan(flags, txts[i], ports, src, output)
			}
		}
		c.Printf("%s端口扫描完成 ", ip)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
	case "vs":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始漏洞扫描: ", urls)
		fmt.Println()
		if file == "" {
			color.Cyan("开始指纹识别")
			FingerScan(urls, flags)
			EHolescan(urls, output)
			color.Cyan("指纹识别结束")
			color.Yellow("开始vulmap扫描")
			Vulmapscan(urls, src, thread, flags)
			color.Yellow("vulmap扫描结束")
			color.Red("开始nuclei扫描")
			Nucleiscan(urls, src, flags)
			color.Red("nuclei扫描结束")
			color.White("开始pocbomber扫描")
			Pocbomberscan(urls, src, thread, flags)
			color.White("pocbomber扫描结束")
			color.Green("开始Find-SomeThing扫描")
			FindSomeThingscan(urls, src, flags)
			color.Green("Find-SomeThing扫描结束")
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				color.Cyan("%s:开始指纹识别", txts[i])
				FingerScan(txts[i], flags)
				EHolescan(txts[i], output)
				color.Cyan("%s:指纹识别结束", txts[i])
				color.Yellow("%s:开始vulmap扫描", txts[i])
				Vulmapscan(txts[i], src, thread, flags)
				color.Yellow("%s:vulmap扫描结束", txts[i])
				color.Red("%s:开始nuclei扫描", txts[i])
				Nucleiscan(txts[i], src, flags)
				color.Red("%s:nuclei扫描结束", txts[i])
				color.White("%s:开始pocbomber扫描", txts[i])
				Pocbomberscan(txts[i], src, thread, flags)
				color.White("%s:pocbomber扫描结束", txts[i])
				color.Green("开始Find-SomeThing扫描")
				FindSomeThingscan(txts[i], src, flags)
				color.Green("Find-SomeThing扫描结束")
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
			Backfilescan(urls, thread)
			Dirsearchscan(urls, thread)
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				Backfilescan(txts[i], thread)
				Dirsearchscan(txts[i], thread)
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
			Dirsearchscan(urls, thread)
			Dirscan(urls, thread)
		} else {
			txts := Readfile(file)
			for i := 0; i < len(txts); i++ {
				fmt.Println("开始扫描:", txts[i])
				Dirsearchscan(txts[i], thread)
				Dirscan(txts[i], thread)
				JsSensitiveData := Finderjs(txts[i])
				for _, v := range JsSensitiveData {
					fmt.Println(v)
				}
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
			JsSensitiveData := Finderjs(urls)
			Katanascan(urls)
			for i := 0; i < len(JsSensitiveData); i++ {
				xrayresult := StartCrawlerGo(JsSensitiveData[i], thread)
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
			Dirsearchscan(urls, thread)
			color.Magenta("目录扫描结束")
			color.Cyan("开始指纹识别")
			FingerScan(urls, flags)
			EHolescan(urls, output)
			color.Cyan("指纹识别结束")
			color.Yellow("开始vulmap扫描")
			Vulmapscan(urls, src, thread, flags)
			color.Yellow("vulmap扫描结束")
			color.Red("开始nuclei扫描")
			Nucleiscan(urls, src, flags)
			color.Red("nuclei扫描结束")
			color.White("开始pocbomber扫描")
			Pocbomberscan(urls, src, thread, flags)
			color.White("pocbomber扫描结束")
			color.Green("开始Find-SomeThing扫描")
			FindSomeThingscan(urls, src, flags)
			color.Green("Find-SomeThing扫描结束")
		} else {
			txts := Readfile(file)
			// 读取全部返回的urls，判断没有协议就加上协议
			for i := 0; i < len(txts)-1; i++ {
				JsSensitiveData := Finderjs(txts[i])
				Katanascan(txts[i])
				for i := 0; i < len(JsSensitiveData); i++ {
					StartCrawlerGo(JsSensitiveData[i], thread)
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
	case "cs":
		start := time.Now() // 获取当前时间
		c.Printf("%s开始c段扫描: ", ip)
		cscan(ip)
		c.Printf("%s扫描完成: ", ip)
		Weak_Pass_Burst.SshScan("sshscan", ip)
		Weak_Pass_Burst.SmbScan("smbscan", ip)
		Weak_Pass_Burst.MysqlScan("mysqlscan", ip)
		Weak_Pass_Burst.MssqlScan("mssqlscan", ip)
		Weak_Pass_Burst.FtpScan("ftpscan", ip)
		Weak_Pass_Burst.MongodbScan("mongodbscan", ip)
		Weak_Pass_Burst.RedisScan("redisscan", ip)
		elapsed := time.Since(start)
		color.Cyan("执行完成耗时：%s", elapsed)
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
	//Webscreenshot(urls)
	//lib.MssqlScan("MSSQLSCAN", "1.116.24.217")
	//cscan("104.21.43.32")
	//Weak_Pass_Burst.SshScan("sshscan", "101.43.49.191")

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
	//端口范围
	flag.StringVar(&src, "src", "", "src，厂商名称 -src 小米")
	//结果输出
	flag.StringVar(&output, "o", "", "--output，结果输出保存到文件")
	//模式选择：默认单站点扫描  all多全流程扫描 vul仅漏洞扫描
	flag.StringVar(&mode, "m", "", "扫描类型，示例 -m all全流程扫描，-m csub 子域名收集， -m fs 指纹识别扫描,-m vs漏洞扫描,不加-m 默认为单url扫描,-m ps端口扫描，-m ds目录扫描 -m sf备份文件+目录扫描,-m rh查看任务数据, -m clear 清除扫描的结果文件")
}

// 按照类型删除扫描结果文件
func SelectPath(ftype string) {
	switch {
	case ftype == ".json":
		TxPortMapresultFilePath := Readyaml("TxPortMap.resultFilePath")
		removetmp(TxPortMapresultFilePath, ftype)
		nucleiexe := Readyaml("nuclei.resultFilePath")
		removetmp(nucleiexe, ftype)
		EHoleexe := Readyaml("EHole.resultFilePath")
		removetmp(EHoleexe, ftype)
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
		Subfinderfile := Readyaml("Subfinder.resultFilePath")
		removetmp(Subfinderfile, ftype)
		pocbomberfile := Readyaml("POC_bomber.resultFilePath")
		removetmp(pocbomberfile, ftype)
		FindSomeThingfile := Readyaml("FindSomeThing.resultFilePath")
		removetmp(FindSomeThingfile, ftype)
		Dirscanfile := Readyaml("dirscan.resultFilePath")
		removetmp(Dirscanfile, ftype)

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
