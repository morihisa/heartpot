#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Python script is a tiny honeypot for Heartbleed(CVE-2014-0160)
# If you use this script by default port(443/tcp), you should run by root.
# 
# Usage: heartpot.py
#
# Output format:
# Date/time, Source IP address, Protocol, Payload
#
# Output example:
# [2014-04-13 01:59:23],192.168.1.22,SSL,1803000003014000
# 
#
# 2014/Apr/13th
# http://www.morihi-soc.net/
# Kazuaki Morihisa (@k_morihisa)

import socket
from contextlib import closing
import binascii
import datetime
import locale

myip = '0.0.0.0'
port = 443

protocols = ["SSL", "TLS1.0", "TLS1.1", "TLS1.2"]

def main():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with closing(sock):
        sock.bind((myip, port))
        sock.listen(10)
        
        while True:
            connection, address = sock.accept()
            while True:
                msg = connection.recv(4096)
                header = binascii.hexlify(msg)[:6]

                if header.startswith("16030"):      # Client Hello
                    connection.sendall(binascii.unhexlify(header + "00010e"))

                elif header.startswith("18030"):    # Heartbeat
                    d = datetime.datetime.today()
                    date = d.strftime("[%Y-%m-%d %H:%M:%S]")
                    protocol = "UNKNOWN"
                    if 0 <= int(header[5]) <= 3:
                        protocol = protocols[int(header[5])]

                    print ("%s,%s,%s,%s") % (date, address[0], protocol, binascii.hexlify(msg))

                else :
                    connection.close()
                    break
        sock.close()

if __name__ == '__main__':
    main()
