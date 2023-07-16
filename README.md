# Aug
一个调用各种扫描工具的启动器，可能有各种问题，可以提lssues，能力范围就修，欢迎各位二开

简单使用命令 
./Aug -u xxx -m xx

  -f string
        file，读取文件内容进行扫描
  -i string
        ip，扫描端口情况，需配合-p 使用
  -m string
        扫描类型，示例 -m all全流程扫描, -m f 读取文件内容扫描,-m vs漏洞扫描,不加-m 默认为单url扫描,-m ps端口扫描,-m ds目录扫描 -m sf备份文件+目录扫描,-m rh查看任务数据, -m clear 清除扫描的结果文件
  -p string
        ports，需要扫描的端口或端口范围,如-p 1-100，-p 100 (default "-t1000")
  -s    save,是否将扫描发现的问题保存到数据库里
  -t int
        thread，输入线程数量。默认50 (default 50)
  -u string
        url，待扫描的url

 主要功能是-m 扫描模式：
     all是根据输入的url，获取子域名，扫描子域名，检查是否存在cdn，waf防护，不存在cdn获取扫描ip top1000端口获取其他http服务，对面收集到的站点进行存活探测指纹识别，js敏感信息收集，爬虫爬取+xray漏洞扫描+中间件poc扫描，结果保存vuln数据库
     不加-m 默认是js敏感信息收集+目录扫描+爬虫xray+漏洞扫描，适用于需要对站点目录扫描+漏洞扫描

 调用了下列工具：
     + 子域名扫描：OneForAll
     + 目录扫描：dirsearch
     + 备份扫描：BackFileScan 
      cdn检测：CDNcheck
      爬虫：crawlergo + katana
      指纹识别：Finger
      js敏感信息：JSFinderPlus
      漏洞扫描：nuclei + POC_bomber + vulmap
      端口扫描：TxPortMap
      获取url多级目录：URLPath
      waf检测：wafw00f
      被动扫描：xray
![image](https://github.com/win1498419293/Aug/assets/44251830/aed5224f-7f4b-417a-9222-54593af3351c)
