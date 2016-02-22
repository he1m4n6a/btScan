#!/usr/bin/env python
#coding=utf8

import os
import sys
import re
import include
import requests
import urlparse
import ConfigParser
from crawl.NetSearch import NetSearch
from scanframe import ScanFrame
from scriptframe import ScriptFrame
from cmdline import parse_args
from ipparse import Ipparse

class AbstractScan():
    def __init__(self, args):
        self.args = args

    '''judge ip legal or not'''
    @staticmethod
    def judegIp(ip):
        ip = str(ip)
        reg = re.compile(r'\d+\.\d+\.\d+\.\d+[\-\/]?[\d]*')
        try:
            return reg.findall(ip)[0]
        except Exception, e:
            return False

    '''parse url or ip_url'''
    def parse_url(self, url_list):
        url_res = []
        for url in url_list:
            try:
                _ = urlparse.urlparse(url, 'http')
                if not _.netloc:
                    _ = urlparse.urlparse('http://' + url, 'http')
                #assert(_.netloc != '')
                if _.port == 443:
                    _url = "https://" + _.netloc
                else:
                    _url = _.scheme + '://' + _.netloc
                if _.path:
                    _url += _.path
                else:
                    _url += '/' 
                url_res.append(_url)
            except Exception, e:
                # print str(e)
                pass
        return url_res

    '''parse ip, support cidr format'''
    def parse_ip(self, ip_list):
        ip_res = []
        for ip in ip_list:
            ip = ip.strip('\n').strip()
            ip = AbstractScan.judegIp(ip)
            if ip:
                pass
            else:
                continue
            #parse cidr
            if '/' in ip or '-' in ip:
                ip_res += Ipparse.listCIDR(ip)
            else:
                ip_res.append(ip)
        return ip_res

    '''get rule from the configuration file'''
    def get_rule(self):
        cf = ConfigParser.ConfigParser()
        cf.read(include.scan_rule_dir)
        items = cf.items("main")
        scan_rule = items[0][1]
        res_rule = items[1][1]
        return scan_rule, res_rule

    '''get payload and method from configuration file'''
    def get_pm(self):
        cf = ConfigParser.ConfigParser()
        cf.read(include.scan_rule_dir)
        items = cf.items("main")
        payload = items[2][1]
        method = items[3][1]
        return payload, method

    '''scan use script method'''
    def scan_script(self):
        thread_num = self.args.t
        script_name = self.args.n
        script_name = "node." +  script_name

        #auto get ip from space search engine
        if self.args.autoIP:
            netsearch = NetSearch()
            ip_list = list(netsearch.getData())
            sscanner = ScriptFrame(ip_list, thread_num, script_name, self.args.c)

        #auto get url from space search engine
        elif self.args.autoURL:
            netsearch = NetSearch()
            url_list = list(netsearch.getData())
            url_list = self.parse_url(url_list)
            sscanner = ScriptFrame(url_list, thread_num, script_name, self.args.c)


        #handle ip file
        elif self.args.i:
            ip_file = self.args.i
            with open(ip_file, 'r') as ip:
                ip_list = ip.read().split('\n')
            func = lambda ip_list: ip_list if ''.join(ip_list[-1:]) else ip_list[:-1]
            ip_list = func(ip_list)
            ip_list = self.parse_ip(ip_list)
            sscanner = ScriptFrame(ip_list, thread_num, script_name, self.args.c)


        #handle url file 
        elif self.args.u:
            url_file = self.args.u
            if not os.path.exists(url_file):
                print "[-]Error Message! Url File not exitst!"
                sys.exit()
            with open(url_file, 'r') as url:
                url_list = url.read().split('\n')
            func = lambda url_list: url_list if ''.join(url_list[-1:]) else url_list[:-1]
            url_list = func(url_list)
            url_list = self.parse_url(url_list)
            sscanner = ScriptFrame(url_list, thread_num, script_name, self.args.c)

        else:
            raise Exception('not url find')

        # sscanner = ScriptFrame(ui_list, thread_num, script_name, self.args.c)
        sscanner.scan()
        sscanner.script_report()

    '''scan specific code, url pattern'''
    def scan_url(self):
        scan_rule, res_rule = self.get_rule()
        payload, method = self.get_pm()
        thread_num = self.args.t
        url_list = []
        #get ip auto from space search engine
        if self.args.autoIP:
            netsearch = NetSearch()
            url_list = list(netsearch.getData())
            url_list = self.parse_url(url_list)
        #get url auto from space search engine
        elif self.args.autoURL:
            netsearch = NetSearch()
            url_list = list(netsearch.getData())
            url_list = self.parse_url(url_list)
        #handle url file
        elif self.args.u:
            url_file = self.args.u
            with open(url_file, 'r') as url:
                url_list = url.read().split('\n')
            func = lambda url_list: url_list if ''.join(url_list[-1:]) else url_list[:-1]
            url_list = func(url_list)
            url_list = self.parse_url(url_list)
        #handle ip file
        elif self.args.i:
            url_file = self.args.i
            with open(url_file, 'r') as url:
                url_list = url.read().split('\n')
            func = lambda url_list: url_list if ''.join(url_list[-1:]) else url_list[:-1]
            url_list = func(url_list)
            url_list = self.parse_url(self.parse_ip(url_list))

        scanner = ScanFrame(url_list, payload, scan_rule, res_rule, method, thread_num)
        scanner.scan()

    '''scanning method'''
    def run(self):
        mode = self.args.m
        #start the mode of config
        if mode == 'config':
            self.scan_url()

        #start the mode of script
        elif mode == 'script':
            self.scan_script()
                     
        else:
            raise Exception('[-]Error Message! You put incorrect mode args')
