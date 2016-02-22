#!/usr/bin/env python
#coding=utf8

import urlparse
import re

class ParseUrl:
    def __init__(self):
        pass

    def judgeIP(self, ip):
        reg = re.compile(r'^(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])$')
        if reg.findall(ip):
            return ip
        else:
            return False

    def parse(self, url):
        _ = urlparse.urlparse(url, 'http')
        if not _.netloc:
                _ = urlparse.urlparse('http://' + url, 'http')
        if _.port:
            return _.netloc.split(':')[0], _.port
        else:
            return _.netloc, 80