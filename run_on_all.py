#!/usr/bin/env python

from pexpect import pxssh
import sys
import subprocess


ips = ["127.0.0.1"]

passwd = 'password'
user = 'user'


def _check_ping(ip, tmo=30):
    try:
        output = subprocess.check_output('ping -c 1 {} -W {}'.format(ip, tmo), shell=True)
    except Exception, e:
        print e
        return False
    return True


def run_commands(cmds, ips):
    ret = []
    for ip in ips:
        if not _check_ping(ip):
            ret.append(ip)
            continue
        ssh = pxssh.pxssh(options={
                    "StrictHostKeyChecking": "no",
                    "UserKnownHostsFile": "/dev/null"}, echo=False)
        ssh.force_password = True
        ssh.logfile = sys.stdout
        print '*' * 20, 'connecting to {}'.format(ip), '*' * 20
        ssh.login(ip, user, passwd)

        ssh.sendline('sudo su -')
        ssh.expect('assword for {}: '.format(user), timeout=60) # full string does not work, since we sometimes miss start of the string
        ssh.sendline(passwd)
        ssh.set_unique_prompt() # we changes user, so let's reset the prompt

        for cmd in cmds:
            ssh.sendline(cmd)
            ssh.prompt()
            output = ssh.before

            ssh.sendline('echo $?')
            ssh.prompt()
            ret_code = int(ssh.before.strip())
            if ret_code != 0:
                 print '!' * 10, 'Error executing command {}: {} output:{}'.format(cmd, ret_code, output)

        ssh.close()
        print '*' * 20, '{} done'.format(ip), '*' * 20
    return ret


def run_all():
    cmds = []
    return run_commands(cmds, ips)


def main():
    failed_hosts = []

    failed_hosts.extend(run_all())

    print 'Failed hosts {}: {}'.format(len(failed_hosts), failed_hosts)


if __name__ == "__main__":
    sys.exit(main())
