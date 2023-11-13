package main

import (
	"Aug/lib"
	"Aug/web"
	"flag"
)

var mode bool

func main() {

	flag.Parse()
	if mode {
		web.Webmain()
	} else {
		lib.Startmain()

	}

}

func init() {
	//是否开启web界面
	flag.BoolVar(&mode, "us", false, "开启终端或者Web，默认开启终端。加上-us开启web模式")
}
