import time
import re
from main import color
from main import logger

def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())
def title():
    color.titlestyle()
#正常的输出
def output(flag,name,url):
    if flag:
        info=now_time()+"[+][SUCCESS] {} : {}".format(name,url)
        logger.logging(info)
        color.green(info)
    else:
        info=now_time()+"[-][WARNING] Not {}".format(name)
        logger.logging(info)
        color.red(info)
#请求的错误        
def ERROR(url):
    info=now_time()+"[-][ERROR] 网络存在波动,目标无响应,请求被拒绝,检查目标是否存活:"
    color.yellow(info)
    print(now_time()+"[-][ERROR] {}".format(url))
    print('--------------------------------------------------------------------------')

#检测的目标
def Tag(url):
    print('--------------------------------------------------------------------------')
    info=now_time()+"正在检测 : {}".format(url)
    logger.logging(info)
    print(info)
    print('--------------------------------------------------------------------------')
    
#框架检测
def FrameOutPut(data):
    #print(data)
    if len(data[1]) > 0 :
        Framename=(data[1])[0].replace('\"', '')
    else:
        Framename=None
    #code=data[3].strip()
    info=now_time()+'\[{}]  {} <{}>  响应大小:{} 权重:{} '.format(Framename,data[0].strip(),data[4].strip(),data[2].strip(),data[5].strip())
    logger.logging(info)
    color.green(info)
def FrameTitle():
    print('--------------------------------------------------------------------------')
    print(now_time()+"框架检测 : ")
    
def updateTitle():
    print('--------------------------------------------------------------------------')
    print(now_time()+"更新yaml规则库 : ")
def updateResult():
    print(now_time()+"更新yaml规则库完成")
    