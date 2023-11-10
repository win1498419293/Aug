package lib

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/spf13/viper"
	"github.com/tealeg/xlsx"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
)

type Autoconfigyaml struct {
	BakFileScan    string `yaml:"BakFileScan"`
	Nuclei         string `yaml:"nuclei"`
	TxPortMap      string `yaml:"TxPortMap"`
	Xray           string `yaml:"xray"`
	Crawlergo      string `yaml:"crawlergo"`
	Finger         string `yaml:"Finger"`
	JSFinderPlus   string `yaml:"JSFinderPlus"`
	CDNcheck       string `yaml:"CDNcheck"`
	ResultFilePath string `yaml:"resultFilePath"`
	Katana         string `yaml:"katana"`
	OneForAll      string `yaml:"OneForAll"`
	URLPath        string `yaml:"URLPath"`
	POCBomber      string `yaml:"POC_bomber"`
	Vulmap         string `yaml:"vulmap"`
	Wafw00f        string `yaml:"wafw00f"`
}

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

func Readhtml(filePath string) []string {
	logfile, err := os.OpenFile("log/readfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	txt := []string{}
	//解决中文乱码
	var enc mahonia.Decoder
	enc = mahonia.NewDecoder("gbk")
	file, err := os.Open(filePath)
	if err != nil {
		log.Println("文件打开失败 = ", err)
	}
	defer file.Close()              // 关闭文本流
	reader := bufio.NewReader(file) // 读取文本数据
	for {
		str, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		//解决中文乱码
		txt = append(txt, enc.ConvertString(str))
		//fmt.Print(str)
	}
	log.SetOutput(logfile)
	return txt
}

// 拆解url获取协议、域名
func Urlchange(urls string) (string, string) {
	u, err := url.Parse(urls)
	if err != nil {
		log.Fatal(err)
	}

	//去除末尾/
	newurls := strings.TrimRight(u.Host, "/")
	// .号分割成数组
	domain := strings.Split(newurls, ".")
	//获取一级域名 如 baidu.com
	newdomain := domain[len(domain)-2] + "." + domain[len(domain)-1]
	return newdomain, u.Host
}

// 读取cvs并返回内容
func ReadSubdomainResult(path string) [][]string {
	cvslens := [][]string{{}}
	//创建日志
	logfile, err := os.OpenFile("log/readfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	cvsfile, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer cvsfile.Close()
	csvReader := csv.NewReader(transform.NewReader(cvsfile, simplifiedchinese.GBK.NewDecoder()))
	csvReader.TrimLeadingSpace = true
	for {
		rec, err := csvReader.Read()
		cvslens = append(cvslens, rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(rec)
	}
	log.SetOutput(logfile)
	return cvslens

}

// 读取xlsx文件
func ReadxlsxResult(xlsxfile string) []string {
	cvslens := []string{}
	xlFile, err := xlsx.OpenFile(xlsxfile)
	if err != nil {
		fmt.Printf("打开Excel文件失败：%s\n", err)
	}

	// 遍历所有工作表
	for _, sheet := range xlFile.Sheets {
		//fmt.Printf("工作表名称：%s\n", sheet.Name)

		// 遍历每行
		for rowindex, row := range sheet.Rows {
			// 跳过第一行，即标题行
			if rowindex == 0 {
				continue
			}
			// 遍历每个单元格
			for _, cell := range row.Cells {
				text := cell.String()
				cvslens = append(cvslens, text)
				//fmt.Printf("%s\t", text)
			}
		}

	}
	return cvslens
}

func Readyaml(parameter string) string {
	// 设置配置文件的名字
	viper.SetConfigName("Config")
	// 设置配置文件的类型
	viper.SetConfigType("yaml")
	// 添加配置文件的路径，指定 config 目录下寻找
	viper.AddConfigPath("./lib")
	// 寻找配置文件并读取
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	para := fmt.Sprintf("%v", viper.Get(parameter))
	return para

}

// 写入txt文件，模式追加
func savetxt(str, path string) {
	filePath := path
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	//及时关闭file句柄
	defer file.Close()
	//写入文件时，使用带缓存的 *Writer
	write := bufio.NewWriter(file)
	// 指定输出编码格式为 GBK
	encoder := simplifiedchinese.GBK.NewEncoder()
	utf8Writer := transform.NewWriter(write, encoder)
	byteArr := []byte(str)
	utf8Writer.Write(byteArr)
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
}

// 写入txt文件，模式新建
func writetxt(str, path string) {
	filePath := path
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	//及时关闭file句柄
	defer file.Close()
	//写入文件时，使用带缓存的 *Writer
	write := bufio.NewWriter(file)
	byteArr := []byte(str)
	newstr := ConvertByte2String(byteArr, "GB18030")
	write.WriteString(newstr)
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
}
