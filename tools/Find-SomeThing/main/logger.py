

def logging(info):
    with open('result/report.txt', 'a+',encoding='utf-8') as f:
        print(info,file = f)