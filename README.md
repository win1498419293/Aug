# Aug
一个调用各种扫描工具的启动器，日常工作中需要使用多个脚本要开多个cmd窗口切换麻烦所以有了这个，可能有各种问题可以提lssues，能力范围就修，代码写的应该比较通俗易懂，欢迎各位根据实际使用需求修改，开源，共享

简单使用命令 
./Aug -u xxx -m xx  


  -f  string  
  
        file，读取文件内容进行扫描  
        
  -i  string  
  
        ip，扫描端口情况，需配合-p 使用  
        
  -m  string  

        扫描类型，示例 -m all全流程扫描, -m f 读取文件内容扫描,-m vs漏洞扫描,不加-m 默认为单url扫描,-m ps端口扫描,-m ds目录扫描 -m sf备份文件+目录扫描,-m rh查看任务数据, -m clear 清除扫描的结果文件  
        
  -p  string  
  
        ports，需要扫描的端口或端口范围,如-p 1-100，-p 100 (default "-t1000")  
        
  -s   bool    
        
        save,是否将扫描发现的问题保存到数据库里  
  
  -t  int  
  
        thread，输入线程数量。默认50 (default 50)  
        
  -u  string  
  
        url，待扫描的url  

![image](https://github.com/win1498419293/Aug/assets/44251830/aed5224f-7f4b-417a-9222-54593af3351c)
  


    
 主要功能是-m 扫描模式：
     扫描模式借鉴：[Suture_Box](https://github.com/F6JO/Suture_Box)
     all是根据输入的url，获取子域名，扫描子域名，检查是否存在cdn，waf防护，不存在cdn获取扫描ip top1000端口获取其他http服务，对面收集到的站点进行存活探测指纹识别，js敏感信息收集，爬虫爬取+xray漏洞扫描+中间件poc扫描，结果保存vuln数据库  
     
     不加-m 默认是js敏感信息收集+目录扫描+爬虫xray+漏洞扫描，适用于需要对站点目录扫描+漏洞扫描  
     
1. 调用了下列工具：
    - 子域名扫描：[OneForAll](https://github.com/shmilylty/OneForAll)
    - 目录扫描：[dirsearch](https://github.com/maurosoria/dirsearch)
    - 备份扫描：[BackFileScan](https://github.com/VMsec/ihoneyBakFileScan_Modify)
    - cdn检测：[CDNcheck](https://github.com/Any3ite/cdnCheck)
    - 爬虫：[crawlergo](https://github.com/Qianlitp/crawlergo) + [katana](https://github.com/projectdiscovery/katana)
    - 指纹识别：[Finger](https://github.com/EASY233/Finger)
    - js敏感信息：[JSFinderPlus](https://github.com/mickeystone/JSFinderPlus)
    - 漏洞扫描：[nuclei](https://github.com/projectdiscovery/nuclei) + [POC_bomber](https://github.com/tr0uble-mAker/POC-bomber) + [vulmap](https://github.com/zhzyker/vulmap)
    - 端口扫描：[TxPortMap](https://github.com/4dogs-cn/TXPortMap)
    - 获取url多级目录：[URLPath](https://github.com/r00tSe7en/URLPath)
    - waf检测：[wafw00f](https://github.com/EnableSecurity/wafw00f)
    -  被动扫描：[xray](https://github.com/chaitin/xray)

2.漏洞扫描结果查看 -m rh，启动http服务,访问本机端口:9999查看子域名数据，任务数据，扫描的漏洞数据，html模版是偷[AUTO-EARN](https://github.com/Echocipher/AUTO-EARN)的，自己主要是不会弄，显示好像还有点问题，只能说能用就行




