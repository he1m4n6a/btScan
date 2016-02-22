#!/usr/bin/env python
#coding=utf8

import os
import sys

p_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_dir = os.path.dirname(os.path.abspath(__file__))
scan_rule_dir = p_dir + os.path.sep + "conf" + os.path.sep + "scan_rule.ini"
crawl_dir = p_dir + os.path.sep + "crawl"
search_rule_dir = crawl_dir + os.path.sep + 'search_rule.ini'

sys.path.append(p_dir)
sys.path.append(lib_dir)
sys.path.append(crawl_dir)
sys.path.append(search_rule_dir)