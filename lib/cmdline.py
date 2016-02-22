#!/usr/bin/env python
#coding=utf8

import argparse
import sys
import os

p_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def check_args(args):
    if not args.m:
        msg = 'Use -m to set attack Mode'
        raise Exception(msg)
    if args.m == 'config' and args.i:
        msg = 'Config mode not support ip format, please use -u'
    if args.autoIP and args.autoURL:
        msg = 'Only use one auto method'
        raise Exception(msg)
    if not args.autoIP and not args.autoURL:
        if not args.u and not args.i:
            msg = 'You should choose a method assign a file'
            raise Exception(msg)
    if args.u and args.i:
        msg = 'Only use -u or -i assign a file'
        raise Exception(msg)
    if args.u and not os.path.isfile(args.u):
        msg = 'TargetFile not found: %s' %args.u
        raise Exception(msg)
    if args.i and not os.path.isfile(args.i):
        msg = 'TargetFile not found: %s' %args.i
        raise Exception(msg)
    if args.m == 'script' and not args.n:
        msg = 'Use -n to choose a script which from node floder' 
        raise Exception(msg)
    if args.n and not os.path.isfile(p_path + os.sep + 'node' + os.sep + args.n + '.py'):
        msg = 'Script name not found: %s.py' %args.n
        raise Exception(msg)
    if args.c not in ('verify', 'exploit'):
        msg = 'Use -c to choose a correct command'
        raise Exception(msg)

def parse_args():
    parser = argparse.ArgumentParser(prog='btScan',
                                    formatter_class=argparse.RawTextHelpFormatter,
                                    description='* batch vulnerability verification and exploition framework. *\nBy he1m4n6a',
                                    usage='btScan.py [options]')
    parser.add_argument('-t', metavar='THREADS', type=int, default=20,
                        help='Num of scan threads for each scan process, 20 by default')
    parser.add_argument('-m', metavar='MODE', type=str, default='',
                        help='select mode [config|script] \ne.g. -m script')
    parser.add_argument('-n', metavar='NAME', type=str,
        help='from node floder choose a script')
    parser.add_argument('-c', metavar='COMMAND', type=str, default='verify',
        help='give an instruction when use script mode [verify|exploit]\ne.g. -c verify')
    parser.add_argument('-u', metavar='URL_FILE', type=str, default='',
                        help='input url file')
    parser.add_argument('-i', metavar='IP_FILE', type=str, default='',
                        help='input ip file')
    parser.add_argument('-autoIP', action='store_true',
                        help='get ip from space search engine and auto attack')
    parser.add_argument('-autoURL', action='store_true',
                        help='get url from space search engine and auto attack')
    parser.add_argument('-v', action='version', version='%(prog)s 1.0    By he1m4n6a')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    check_args(args)
    return args