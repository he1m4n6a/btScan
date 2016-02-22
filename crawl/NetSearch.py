#!/usr/bin/env python
#coding=utf8

import sys
import os
from censys import *
import censys
import shodan
import ConfigParser
sys.path.append('../lib')
import include

class CensysClass:
    #max request 120 times per 5 minutes.
    def __init__(self, querystr, start_page=1, max_page=10):
        self.api_id = ""
        self.api_secret = ""
        self.querystr = querystr
        self.START_PAGE = start_page
        self.MAX_PAGE = max_page

    #get ipv4 data
    def ipv4_data(self):
        reslist = []
        API_ID = self.api_id
        API_SECRET = self.api_secret
        try:
            api = censys.ipv4.CensysIPv4(api_id=API_ID, api_secret=API_SECRET)
            import pdb
            pdb.set_trace()
            res = api.search(self.querystr)
            matches = res['metadata']['count']
            pageNum = matches / 100
            maxPageNum = pageNum
            if matches % 100 != 0:
                pageNum = pageNum + 1
            pageNum = self.MAX_PAGE if pageNum > self.MAX_PAGE else pageNum
            count = 1
            while count <= pageNum:
                if self.START_PAGE > maxPageNum:
                    break
                results = api.search(self.querystr, page=self.START_PAGE)
                count = count + 1
                self.START_PAGE = self.START_PAGE + 1
                for result in results.get('results'):
                    #rr = "{0}:{1}".format(result.get("ip"), result.get('protocols')[0].split('/')[0])
                    rr = "{0}".format(result.get("ip"))
                    reslist.append(str(rr))
            return reslist
            # print  reslist
        except Exception, e:
            print str(e)

    #get website data
    def websites_data(self):
        reslist = []
        API_ID = self.api_id
        API_SECRET = self.api_secret
        try:
            api = censys.websites.CensysWebsites(api_id=API_ID, api_secret=API_SECRET)
            res = api.search(self.querystr)
            matches = res['metadata']['count']
            pageNum = matches / 100
            maxPageNum = pageNum
            if matches % 100 != 0:
                pageNum = pageNum + 1
            pageNum = self.MAX_PAGE if pageNum > self.MAX_PAGE else pageNum
            count = 1
            while count <= pageNum:
                if self.START_PAGE > maxPageNum:
                    break
                results = api.search(self.querystr, page=self.START_PAGE)
                count = count + 1
                self.START_PAGE = self.START_PAGE + 1
                for result in results.get('results'):
                    rr = result.get('domain')
                    reslist.append(str(rr))
            return reslist
            # print reslist
        except Exception, e:
            print str(e)

class ShodanClass: 
    #Free users only 100 item with 1 pages
    def __init__(self, querystr, MAX_PAGE=1):
        self.SHODAN_API_KEY = ""
        self.querystr = querystr
        self.MAX_PAGE = MAX_PAGE 
        
    def raw_data(self):
        SHODAN_API_KEY = self.SHODAN_API_KEY
        reslist = []
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            results = api.search(self.querystr, page=self.MAX_PAGE)
            for result in results['matches']:
                rr = "{0}:{1}".format(result['ip_str'], str(result['port']))
                reslist.append(str(rr))
            return reslist
            # print reslist
        except Exception, e:
            print str(e)


class NetSearch:
    def __init__(self):
        self.conf_file = include.search_rule_dir

    def getData(self):
        try:
            censys_list = []
            shodan_list = []
            cf = ConfigParser.ConfigParser()
            cf.read(self.conf_file)
            censys_items = cf.items("censys")
            shodan_items = cf.items("shodan")
            censys_start = censys_items[0][1]
            censys_mode = censys_items[1][1]
            censys_querystr = censys_items[2][1]
            censys_start_page = int(censys_items[3][1])
            censys_max_page = int(censys_items[4][1])
            shodan_start = shodan_items[0][1]
            shodan_querystr = shodan_items[1][1]
            shodan_max_page = int(shodan_items[2][1])
            # print censys_start, censys_mode, censys_querystr, censys_start_page, censys_max_page, shodan_start, shodan_querystr, shodan_max_page

            if censys_start == 'on':
                censys_class = CensysClass(censys_querystr, censys_start_page, censys_max_page)
                if censys_mode == "websites":
                    censys_list = censys_class.websites_data()
                elif censys_mode == "ipv4":
                    censys_list = censys_class.ipv4_data()
                else:
                    msg = "error args"
                    print msg
                    exit(0)
            if shodan_start == 'on':
                shodan_class = ShodanClass(shodan_querystr, shodan_max_page)            
                shodan_list = shodan_class.raw_data()

            if censys_list and shodan_list:
                rset = set(censys_list+shodan_list)
                return rset
            elif censys_list:
                rset = set(censys_list)
                return rset
            elif shodan_list:
                rset = set(shodan_list)
                return shodan_list
            else:
                msg = 'None result'
                print msg
                exit(0)
        except Exception, e:
            print str(e)

if __name__ == '__main__':
    fout = open('out.txt', 'w')
    netsearch = NetSearch()
    rset = netsearch.getData()
    if rset != None:
        for s in rset:
            fout.write(s+'\n')
    else:
        print 'rset is none'
        fout.close()
        sys.exit()
    print "\ntask all over.\n"
    fout.close()