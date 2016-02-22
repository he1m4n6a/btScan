#!/usr/bin/env python
#coding=utf8

import re
import requests
import include
import ConfigParser
from Queue import Queue
from threading import Thread, Lock

method = None

class ScanFrame:
    def __init__(self, url_list, payload, scan_rule, res_rule, method, thread_num):
        self.url_list = url_list
        self.payload = payload
        self.scan_rule = scan_rule
        self.res_rule = res_rule
        self.method = method
        self.thread_num = thread_num

    '''handle get method'''
    def scan(self):
        f = open('res.txt', 'w')
        queue = Queue()
        #start thread_num thread
        for i in xrange(self.thread_num):
            worker = ScanWorker(queue)
            worker.daemon = True
            worker.start()

        #Add links to the queue
        for url in self.url_list:
            if self.method == "get":
                if self.payload:
                    url_full = url + self.payload
                else:
                    url_full = url
                queue.put((url_full, f, self.scan_rule, self.res_rule))

            if self.method == "post":
                if self.payload:
                    url_full = url
                    data = dict([tuple(x.split("=")) for x in self.payload.split("&")])
                    queue.put((url, f, data, self.scan_rule, self.res_rule))

        queue.join()
        f.close()

'''work threads'''
class ScanWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        cf = ConfigParser.ConfigParser()
        cf.read(include.scan_rule_dir)
        items = cf.items("main")
        method = items[3][1]
        while True:
            # handle get method
            if method == "get":
                url_full, f, scan_rule, res_rule = self.queue.get()
                try:
                    r = requests.get(url_full, verify=False)
                    if r.status_code != 200:
                        # raise Exception
                        mlock = Lock()
                        mlock.acquire()
                        mlock.release()
                    page_content = r.content
                    scan_reg = re.compile(r'%s' %scan_rule)
                    res_reg = None
                    if res_rule:
                        res_reg = re.compile(r'%s' %res_rule)
                    res = url_full
                    if scan_reg.search(page_content) != None:
                        #if define reg_rule, get reg result
                        if res_reg:
                            if res_reg.findall(page_content) != []:
                                for item in res_reg.findall(page_content):
                                    res += "\t" + item
                                res += "\n"
                                mlock = Lock()
                                mlock.acquire()
                                print "[+]%s" %res
                                f.write(res)
                                mlock.release()
                            else:
                                mlock = Lock()
                                mlock.acquire()
                                print "[-]%s" %url_full
                                mlock.release()
                        #just only judge exploit or not
                        else:
                            mlock = Lock()
                            mlock.acquire()
                            print "[+]%s" %url_full
                            f.write(url_full+'\n')
                            mlock.release()
                    else:
                        mlock = Lock()
                        mlock.acquire()
                        print "[-]%s" %url_full
                        mlock.release()
                except Exception, e:
                    print str(e)
                    pass
                self.queue.task_done()

            # handle post method
            if method == "post":
                url_full, f, data, scan_rule, res_rule = self.queue.get()
                try:
                    r = requests.post(url_full, data=data, verify=False)
                    page_content = r.content
                    scan_reg = re.compile(r'%s' %scan_rule)
                    res_reg = None
                    if res_rule:
                        res_reg = re.compile(r'%s' %res_rule)
                    res = url_full
                    if scan_reg.search(page_content) != None:
                        #if define reg_rule, get reg result
                        if res_reg:
                            if res_reg.findall(page_content) != []:
                                for item in res_reg.findall(page_content):
                                    res += "\t" + item
                                    res += "\n"
                                mlock = Lock()
                                mlock.acquire()
                                print "[+]%s" %res
                                f.write(res)
                                mlock.release()
                            else:
                                mlock = Lock()
                                mlock.acquire()
                                print "[-]%s" %url_full
                                mlock.release()
                        #just only judge exploit or not
                        else:
                            mlock = Lock()
                            mlock.acquire()
                            print "[+]%s" %url_full
                            f.write(url_full)
                            mlock.release()
                    else:
                        mlock = Lock()
                        mlock.acquire()
                        print "[-]%s" %url_fulls
                        mlock.release()
                except Exception, e:
                    print str(e)
                    pass
                self.queue.task_done()