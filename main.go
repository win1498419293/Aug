package main

import (
	"Aug/web"
	"flag"
)

var mode bool

func main() {
	web.Webmain()
	/*
		flag.Parse()
		if mode {
			lib.Startmain()
		} else {
			web.Webmain()
		}

	*/
}

func init() {
	//是否保存扫描发现的漏洞到数据库
	flag.BoolVar(&mode, "us", false, "开启终端或者Web，默认开启web。加上-us使用终端模式")
}
