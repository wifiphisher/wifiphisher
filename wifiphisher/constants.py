#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os

# Basic configuration
PORT = 8080
SSL_PORT = 443
PEM = 'wifiphisher/cert/server.pem'
PHISHING_PAGES_DIR = "wifiphisher/phishing-pages/"
POST_VALUE_PREFIX = "wfphshr"
NETWORK_IP = "10.0.0.0"
NETWORK_MASK = "255.255.255.0"
NETWORK_GW_IP = "10.0.0.1"
DHCP_LEASE = "10.0.0.2,10.0.0.100,12h"
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
