package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/bigpwdattack"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func TestBigPWDATTACk(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/bigpwdattack.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, bigpwdattack.StartTesting)
	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = "127.0.0.1:7777"
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	pluginInternal := plugin.Plugin{
		PluginName:   "BigPwdAttack",
		PluginId:     plugin.BigPwdAttack,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      30 * time.Second,
	}
	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		Rate:     &Ratelimite,
		Config:   TaskConfig,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
