#!/usr/bin/env python
#coding=utf8

import os
import glob
import sys
from string import Template
import time
import webbrowser
from optparse import OptionParser
from lib.cmdline import parse_args
from lib.scancore import AbstractScan
from lib.report import TEMPLATE_html

args = parse_args()

def main():
    scanner = AbstractScan(args)
    scanner.run()

if __name__ == '__main__':
    main()