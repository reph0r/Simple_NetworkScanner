#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @author:CVultra
# @time:2022/7/5

#--------------------------------------------------------------
import nmap
import sys
from optparse import OptionParser
from scapy.all import *
import time
import os
import threading
import socket
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool
from whois import *
import requests

#--------------------------------------------------------------

#--------------------------------------------------------------
def Welcome():
    Welcome = """

/***
 *                    .::::.
 *                  .::::::::.
 *                 :::::::::::  
 *             ..:::::::::::'
 *           '::::::::::::'
 *             .::::::::::
 *        '::::::::::::::..
 *             ..::::::::::::.
 *           ``::::::::::::::::
 *            ::::``:::::::::'        .:::.
 *           ::::'   ':::::'       .::::::::.
 *         .::::'      ::::     .:::::::'::::.
 *        .:::'       :::::  .:::::::::' ':::::.
 *       .::'        :::::.:::::::::'      ':::::.
 *      .::'         ::::::::::::::'         ``::::.
 *  ...:::           ::::::::::::'              ``::.
 * ```` ':.          ':::::::::'                  ::::..
 *                    '.:::::'                    ':'````..
 */
        """

    print(Welcome)

#--------------------------------------------------------------
#1.主机扫描
def ping_ip(ip_str):
    cmd = ["ping", "-n 1", "-v 1", ip_str]
    resopnse = os.popen(" ".join(cmd)).readlines()
    ip_list = []
    flag = False
    for line in list(resopnse):
        if not line:
            continue
        if str(line).upper().find("TTL") >= 0:
            flag = True
            break

    if flag:
        print(ip_str+' 主机存活!')
        #ip_list.append(str(ip_str))
    else:
        print(ip_str,' 主机不存在!')
        pass

#--------------------------------------------------------------
#2.端口扫描
class ScanPort:
    def __init__(self):
        self.ip = None

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            res = s.connect_ex((self.ip, port))
            if res == 0:  # 端口开启
                print('Ip:{} Port:{} 端口 开启'.format(self.ip, port))
            #else:
                #print('Ip:{} Port:{}: IS NOT OPEN'.format(self.ip, port))
        except Exception as e:
            print(e)
        finally:
            s.close()

    def start(self):
        remote_server = input("输入要扫描的远程主机:")
        self.ip = socket.gethostbyname(remote_server)
        ports = [i for i in range(1, 1025)]
        socket.setdefaulttimeout(0.5)
        # 开始时间
        t1 = datetime.now()
        # 设置多进程
        threads = []
        pool = ThreadPool(processes=8)
        pool.map(self.scan_port, ports)
        pool.close()
        pool.join()

        print('端口扫描已完成，耗时：', datetime.now() - t1)

#--------------------------------------------------------------
#3.操作系统判断
def guess_os_nmap(ip):
    """
    1.调用第三方库nmap进行系统扫描，判断操作系统
    2，如果再Windows系统下，需要先行安装ncap软件，才能正确执行代码
    :param ip:
    :return:
    """
    nm = nmap.PortScanner()
    try:
        result = nm.scan(hosts=ip,arguments='-0')
        os = result["scan"][ip]['osmatch'][0]['name']
        time.sleep(0.1)
        print(ip,os)
    except:
        pass

#--------------------------------------------------------------
#4.识别CDN
def if_have_cdn(url):
    os_command = os.popen('nslookup %s'%url)
    #读取系统执行的命令
    os1 = os_command.read()
    #print(os1)
    number = os1.count(".")
    if number <= 10:
        print("[+]初步判断该网站没有CDN")
    else:
        print("[+]初步判断该网站具有CDN")

#--------------------------------------------------------------
#5.域名反查IP
def get_ip(url):
    ip = socket.gethostbyname(url)
    print(ip)

#--------------------------------------------------------------
#6.whois查询
def check_whois(url):
    data = whois('%s'%url)
    print(data)

#--------------------------------------------------------------
def zym_check(url):
    urls = url.replace('www','')
    for zym_data in open('dic.txt'):
        zym_data = zym_data.replace('\n','')
        url = zym_data+urls
        try:
            ip = socket.gethostbyname(url)
            #r = requests.get('https://code.xueersi.com/')
            url = 'https://'+url
            r = requests.get(url)
            if(r.status_code == 200):
                print(url + '->' + ip)

            #time.sleep(0.2)
        except Exception as e:
            pass



#--------------------------------------------------------------

if __name__ == '__main__':

    Welcome()

    while True:
        print('''
        -----选择功能-----
        1.主机扫描
        2.端口扫描
        3.操作系统判断
        4.查询CDN
        5.域名反查IP
        6.whois查询
        7.子域名查询
        q.退出
        -----选择功能-----
        ''')
        choice = input("选择功能>>>")
        try:
            if choice == '1':
                print("Welcome to Host_Scanner,example:127.0.0.\n")
                ip_list = input("请输入您需要测试的IP段：>>>\n")
                for i in range(1, 256):
                    ip = (ip_list + str(i))
                    scan = threading.Thread(target=ping_ip, args=(ip,))
                    scan.start()
                    time.sleep(0.3)
            elif choice == '2':
                ScanPort().start()
            elif choice == '3':
                ip = input("请输入待判断操作系统的IP：>>>")
                guess_os_nmap()
            elif choice == '4':
                url = input("请输入待判断CDN的URL：>>>")
                if_have_cdn(url)
            elif choice == '5':
                url = input("请输入您需要查询IP的URL：>>>")
                get_ip(url)
            elif choice == '6':
                url = input("请输入您需要whois查询的URL：>>>")
                check_whois(url)
            elif choice == '7':
                url = input("请输入您需要查询子域名的域名：>>>")
                zym_check(url)

            elif choice == 'q':
                break
            else:
                print("输入错误！！")
        except Exception:
            pass
