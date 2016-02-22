#!/usr/bin/env python
#coding=utf8

import psycopg2
import sys

username = ['postgres', 'root']
weakpass = ['', 'postgres', '123456', 'root']

def verify(host):    
    port = '5432'
    for user in username:
        for password in weakpass:
            try:
                conn = psycopg2.connect(host=host, port=port, user=user, password=password)
                msg = 'vul'
                return True, host, msg
            except Exception, e:
                return False, host, str(e)