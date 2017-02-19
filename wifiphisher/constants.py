#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#pylint: skip-file
import os

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(
    os.path.join(dir_of_executable, '../wifiphisher'))
dir_of_data = path_to_project_root + '/data/'

# Basic configuration
PORT = 8080
SSL_PORT = 443
CHANNEL = 6
PUBLIC_DNS = "8.8.8.8"
PEM = dir_of_data + 'cert/server.pem'
PHISHING_PAGES_DIR = dir_of_data + "phishing-pages/"
LOGOS_DIR = dir_of_data + "logos/"
MAC_PREFIX_FILE = dir_of_data + "wifiphisher-mac-prefixes"
POST_VALUE_PREFIX = "wfphshr"
NETWORK_IP = "10.0.0.0"
NETWORK_MASK = "255.255.255.0"
NETWORK_GW_IP = "10.0.0.1"
DHCP_LEASE = "10.0.0.2,10.0.0.100,12h"
WIFI_BROADCAST = "ff:ff:ff:ff:ff:ff"
WIFI_INVALID = "00:00:00:00:00:00"
WIFI_IPV6MCAST1 = "33:33:00:"
WIFI_IPV6MCAST2 = "33:33:ff:"
WIFI_SPANNINGTREE = "01:80:c2:00:00:00"
WIFI_MULTICAST =  "01:00:5e:"
LINES_OUTPUT = 3
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
