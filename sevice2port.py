#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import re
import os

def execute_nmap(commad):
    """execute a command with super admin priviledge

    :commad: TODO
    :returns: TODO

    """
    cmd_list = commad.split(' ')
    ports = []
    portline_reg = "(\d+)\/(tcp|udp)\s+(closed|open|filter)\s+[^\s]+"
    portline_re = re.compile(portline_reg)
    try:
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE).communicate()
        (info, err) = process
        info = info.decode('ascii')
    except OSError as e:
        print('nmap may not be installed correctly.')
        raise e
    for item in info.split('\n'):
        match = re.search(portline_re, item)
        if match:
            ports.append(':'+match.group(1))

    return ports

def get_pid(ports):
    """TODO: Docstring for get_pid.

    :port: TODO
    :returns: TODO

    """
    pair = {}
    cmd = ['lsof', '-i']
    pname = ''
    pid = ''

    for port in ports:
        pid_pname_list = []
        cmd.append(port)

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()
            (info, err) = process
            info = info.decode('ascii')
        except OSError as e:
            raise e

        for line in info.split('\n'):
            if line:
                pid   = line.split()[1]
                pname = get_pname(pid)
            if 'PID' in pid:
                continue
            pid_pname_list.append([pid, pname])

        pair[port] = [list(x) for x in set(tuple(x) for x in pid_pname_list)]
        cmd.pop(2)

    return pair

def get_pname(pid):
    """get process name by pid
    :returns: TODO

    """
    pid_path = os.path.join('/proc', pid)
    if os.path.exists(pid_path):
        with open(os.path.join(pid_path, 'comm')) as f:
            pname = f.read().rstrip('\n')
            return pname

def main():
    """TODO: Docstring for main.
    :returns: TODO

    """
    cmd = "nmap -p1-65535 localhost"
    ports = execute_nmap(cmd)
    pair= get_pid(ports)
    print("%7s %8s %15s" % ('PORT', 'PID', 'PROCESS'))
    for port, pid_pname_list in pair.items():
        for item in pid_pname_list:
            item.insert(0, port.replace(':', ''))
            print("%7s %8s %15s" % tuple(item))

if __name__ == "__main__":
    main()
