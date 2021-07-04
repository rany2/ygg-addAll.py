#!/usr/bin/env python3

import os
import re
import time
import socket
import argparse
import threading

def is_ipv4(value):
    try:
        socket.inet_aton(value)
        return True
    except:
        return False

def is_ipv6(value):
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except:
        return False

def is_domain(value):
    # Regex from https://github.com/kvesteri/validators/blob/master/validators/domain.py#L5-L10
    return re.match(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
        , value.encode('idna').decode('ascii')
    )

def ping(address, port, match, results):
    try:
        if is_ipv4(address):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif is_ipv6(address):
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        elif is_domain(address):
            try:
                address = socket.getaddrinfo(address, None, socket.AF_INET6)[0][4][0]
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            except socket.gaierror:
                address = socket.gethostbyname(address)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout (0.5) # who wants a peer worse than 0.5 sec?
        start = time.perf_counter()
        s.connect((address, port))
        result = (time.perf_counter() - start) * 1000
        s.close()
        return results.update({match: result})
    except:
        return results.update({match: float('inf')})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Yggdrasil Public Peer Compiler")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--blacklist', help='blacklists peer file (delimited by space)')
    group.add_argument('-w', '--whitelist', help='whitelists peer file (delimited by space)')

    parser.add_argument(
        '-d',
        '--peer-directory',
        default='.',
        help='peer directory (default pwd)'
    )

    parser.add_argument(
        '-p',
        '--protocol',
        help='only show specified protocol (delimited by space) (default tcp, tls for -46a and all for everything else)'
    )

    parser.add_argument('--ping', help='ping all address', action='store_true')

    parser.add_argument('-4', '--ipv4', help='only show ipv4 peers', action='store_true')
    parser.add_argument('-6', '--ipv6', help='only show ipv6 peers', action='store_true')
    parser.add_argument('-a', '--dns', help='only show dns peers', action='store_true')

    args = parser.parse_args()

    if args.blacklist is not None:
        args.blacklist = args.blacklist.split(' ')
        args.blacklist = [ i.split('.')[0].lower() for i in args.blacklist ]

    if args.whitelist is not None:
        args.whitelist = args.whitelist.split(' ')
        args.whitelist = [ i.split('.')[0].lower() for i in args.whitelist ]

    if args.protocol is not None:
        args.protocol = args.protocol.split(' ')
    else:
        if args.ipv4 or args.ipv6 or args.dns or args.ping:
            args.protocol = ['tcp','tls']
        else:
            args.protocol = ['tcp','tls','socks']

    if args.ping:
        results = {}
        if not args.ipv4 and not args.ipv6 and not args.dns:
            args.ipv4 = True
            args.ipv6 = True
            args.dns = True

    for dir in [
        os.path.join(args.peer_directory, i)
        for i in os.listdir(args.peer_directory)
        if os.path.isdir(os.path.join(args.peer_directory, i)) and i not in ['.git']
    ]:
        for file in os.listdir(dir):
            file_no_ext = file.split('.')[0].lower()

            if args.blacklist is not None and file_no_ext in args.blacklist:
                continue
            if args.whitelist is not None and file_no_ext not in args.whitelist:
                continue

            try:
                if file.split('.')[-1] == 'md' and os.path.isfile(os.path.join(dir, file)):
                    with open(os.path.join(dir, file), 'r') as f:
                        for line in f:
                            for match in re.findall(r'\*\s*`(.*?)`', line):
                                proto = match.split(':')[0]
                                if proto not in args.protocol:
                                    continue

                                if args.ipv4 or args.ipv6 or args.dns:
                                    host = match.split('/')[2]

                                    try:
                                        if args.ipv4 and is_ipv4(host.split(':')[0]):
                                            if not args.ping:
                                                print(match, flush=True)
                                            else:
                                                threading.Thread(
                                                    target=ping,
                                                    args=(host.split(':')[0], int(host.split(':')[1].split('?')[0]), match, results)
                                                ).start()
                                            continue
                                    except:
                                        pass

                                    try:
                                        if args.ipv6 and is_ipv6(host.split('[')[1].split(']')[0]):
                                            if not args.ping:
                                                print(match, flush=True)
                                            else:
                                                threading.Thread(
                                                    target=ping,
                                                    args=(host.split('[')[1].split(']')[0], int(host.split(']')[1].split(':')[1].split('?')[0]), match, results)
                                                ).start()
                                            continue
                                    except:
                                        pass

                                    try:
                                        if args.dns and is_domain(host.split(':')[0]):
                                            if not args.ping:
                                                print(match, flush=True)
                                            else:
                                                threading.Thread(
                                                    target=ping,
                                                    args=(host.split(':')[0], int(host.split(':')[1].split('?')[0]), match, results)
                                                ).start()
                                            continue
                                    except:
                                        pass
                                else:
                                    print(match, flush=True)
            except:
                pass

    if args.ping:
        while threading.active_count() > 1:
            time.sleep(0.01)
        total_length = []
        for length in sorted(results.keys(), key=lambda x: len(x), reverse=True):
            # Don't count dead peers for max length
            if results[length] != float('inf'):
                max_length = len(length) + 4
                break
        column_one = "Peer"
        print ("%s%s%s" % (column_one, " " * (max_length - len(column_one)), "Ping result"))
        for result in sorted(results.items(), key=lambda x: x[1]):
            # Don't show dead peers
            if result[1] != float('inf'):
                print ("%s%s%.03f ms" % (result[0], " " * (max_length - len(result[0])), result[1]))
