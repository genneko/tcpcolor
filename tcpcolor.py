#!/usr/bin/env python3
import sys, os, dpkt, socket
from dpkt.ethernet import ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_IP6
from dpkt.arp import ARP_OP_REQUEST, ARP_OP_REPLY
from dpkt.ip import IP_PROTO_ICMP, IP_PROTO_ICMP6, IP_PROTO_IGMP, IP_PROTO_TCP, IP_PROTO_UDP
from dpkt.icmp import ICMP_ECHO, ICMP_ECHOREPLY
from dpkt.icmp6 import ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY
from dpkt.compat import compat_ord

_ipnum = ord('A');
_ipdic = {}
_macnum = ord('A');
_macdic = {'ff:ff:ff:ff:ff:ff': 'Broadcast'}

class Color:
    DARKGRAY = '\033[1;30;40m'
    RED      = '\033[1;31;40m'
    GREEN    = '\033[1;32;40m'
    YELLOW   = '\033[1;33;40m'
    BLUE     = '\033[1;34;40m'
    MAGENTA  = '\033[1;35;40m'
    CYAN     = '\033[1;36;40m'
    WHITE    = '\033[1;37;40m'
    END = '\033[0m'

#
# mac_addr() and ip_addr() functions is taken from:
# https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py
#
"""
  Copyright (c) 2004 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The names of the authors and copyright holders may not be used to
     endorse or promote products derived from this software without
     specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    global _macnum, _macdic
    mac = ':'.join('%02x' % compat_ord(b) for b in address)
    if mac not in _macdic:
        _macdic[mac] = chr(_macnum)
        _macnum += 1
    return mac


def ip_addr(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    global _ipnum, _ipdic
    # First try ipv4 and then ipv6
    try:
        ip = socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        ip = socket.inet_ntop(socket.AF_INET6, inet)
    if ip not in _ipdic:
        _ipdic[ip] = chr(_ipnum)
        _ipnum += 1
    return ip

def l4_port(port, both=True):
    """Convert a port number to a service name
    """
    try:
        name = socket.getservbyport(port)
        if both:
            name = "{} ({})".format(name, port)
    except:
        name = str(port)
    return name

def print_arp(eth):
    arp = eth.arp
    print("ARP ", end="")

    if arp.op == ARP_OP_REQUEST:
        print("Request")
        print("    What's the MAC address for " + Color.YELLOW + "{}"
                .format(ip_addr(arp.tpa)) + Color.END + "?")
    elif arp.op == ARP_OP_REPLY:
        print("Reply")
        print("    It's " + Color.YELLOW + "{}".format(mac_addr(arp.sha)) + Color.END + ".")
    else:
        print("OP {}".format(arp.op))
    print("    I'm {} at {}."
            .format(ip_addr(arp.spa),
                mac_addr(arp.sha)))

def print_ipv4(eth):
    ip = eth.data
    print("IPv4")
    print(Color.MAGENTA + "    {} -> {} "
            .format(ip_addr(ip.src), ip_addr(ip.dst)) + Color.END +
            "(id={}{}) ".format(ip.id, (",M" if ip.mf else "")), end="")

    if ip.offset > 0:
        print("FRAG({})".format(ip.offset))
    elif ip.p == IP_PROTO_ICMP:
        print_icmp(ip)
    elif ip.p == IP_PROTO_IGMP:
        print("IGMP")
    elif ip.p == IP_PROTO_TCP:
        print_tcp(ip)
    elif ip.p == IP_PROTO_UDP:
        print_udp(ip)
    else:
        print("IPPROTO {}".format(ip.p))

def print_ipv6(eth):
    ip = eth.data
    print("IPv6")
    print(Color.MAGENTA + "    {} -> {} "
            .format(ip_addr(ip.src), ip_addr(ip.dst)) + Color.END, end="")

    if ip.nxt == IP_PROTO_ICMP6:
        print_icmp6(ip)
    if ip.nxt == IP_PROTO_TCP:
        print_tcp(ip)
    elif ip.nxt == IP_PROTO_UDP:
        print_udp(ip)
    else:
        print("IPPROTO {}".format(ip.nxt))

def print_tcpudp(ip, proto):
    pdu = ip.data
    print("{} ".format(proto))
    print(Color.CYAN + "    {} -> {} "
            .format(l4_port(pdu.sport), l4_port(pdu.dport)) + Color.END)

def print_tcp(ip):
    print_tcpudp(ip, "TCP")

def print_udp(ip):
    print_tcpudp(ip, "UDP")

def print_icmp(ip):
    icmp = ip.data
    print("ICMP ", end="")

    if icmp.type == ICMP_ECHO:
        echo = icmp.data
        print("Echo Request (id {}, seq {})".format(echo.id, echo.seq))
    elif icmp.type == ICMP_ECHOREPLY:
        echo = icmp.data
        print("Echo Reply (id {}, seq {})".format(echo.id, echo.seq))
    else:
        print("Type {}/Code {}".format(icmp.type, icmp.code))

def print_icmp6(ip):
    icmp = ip.data
    print("ICMP ", end="")

    if icmp.type == ICMP6_ECHO_REQUEST:
        echo = icmp.data
        print("Echo Request (id {}, seq {})".format(echo.id, echo.seq))
    elif icmp.type == ICMP6_ECHO_REPLY:
        echo = icmp.data
        print("Echo Reply (id {}, seq {})".format(echo.id, echo.seq))
    else:
        print("Type {}/Code {}".format(icmp.type, icmp.code))

def main():
    if(len(sys.argv) > 1):
        f = open(sys.argv[1], 'rb')
    else:
        f = os.fdopen(sys.stdin.fileno(), 'rb')
    p = dpkt.pcap.Reader(f)

    print()
    for t, buf in p:
        eth = dpkt.ethernet.Ethernet(buf)
        print(Color.GREEN + "{} -> {} "
                .format(mac_addr(eth.src), mac_addr(eth.dst))
                + Color.END, end="")

        if eth.type == ETH_TYPE_ARP:
            print_arp(eth)
        elif eth.type == ETH_TYPE_IP:
            print_ipv4(eth)
        elif eth.type == ETH_TYPE_IP6:
            print_ipv6(eth)
        else:
            print("Unknown(%04X)" % eth.type)
        print()

if __name__ == "__main__":
    main()

