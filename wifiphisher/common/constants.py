#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: skip-file

import os

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(
    os.path.join(dir_of_executable, '../../wifiphisher'))
dir_of_data = path_to_project_root + '/data/'
phishing_pages_dir = dir_of_data + "phishing-pages/"

# Basic configuration
DEV = 1
DEAUTH_EXTENSION = "deauth"
LURE10_EXTENSION = "lure10"
WPSPBC = "wpspbc"
KNOWN_BEACONS_EXTENSION = "knownbeacons"
HANDSHAKE_VALIDATE_EXTENSION = "handshakeverify"
ROGUEHOSTAPDINFO = "roguehostapdinfo"
DEFAULT_EXTENSIONS = [DEAUTH_EXTENSION]
EXTENSIONS_LOADPATH = "wifiphisher.extensions."
PORT = 8080
SSL_PORT = 443
CHANNEL = 6
WEBSITE = "https://wifiphisher.org"
PUBLIC_DNS = "8.8.8.8"
PEM = dir_of_data + 'cert/server.pem'
SCENARIO_HTML_DIR = "html/"
LOGOS_DIR = dir_of_data + "logos/"
LOCS_DIR = dir_of_data + "locs/"
MAC_PREFIX_FILE = dir_of_data + "wifiphisher-mac-prefixes"
URL_TO_OS_FILE = dir_of_data + "wifiphisher-os-initial-requests"
KNOWN_WLANS_FILE = dir_of_data + "wifiphisher-known-open-wlans"
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
WIFI_MULTICAST = "01:00:5e:"
NON_CLIENT_ADDRESSES = set([
    WIFI_BROADCAST, WIFI_INVALID, WIFI_MULTICAST, WIFI_IPV6MCAST1,
    WIFI_IPV6MCAST2, WIFI_SPANNINGTREE, None
])
DEFAULT_OUI = '00:00:00'
LINES_OUTPUT = 3
DN = open(os.devnull, 'w')
INTERFERING_PROCS = [
    "wpa_action", "wpa_supplicant", "wpa_cli", "dhclient", "ifplugd", "dhcdbd",
    "dhcpcd", "udhcpc", "avahi-autoipd", "avahi-daemon", "wlassistant",
    "wifibox", "NetworkManager", "knetworkmanager"
]
DNS_CONF_PATH = '/tmp/dnsmasq.conf'
NEW_YEAR = "01-01"
BIRTHDAY = "01-05"

# Modes of operation
# AP, Extensions
# 2 cards, 2 interfaces
# i) AP, ii) EM
OP_MODE1 = 0x1
# AP, Extensions and Internet
# 3 cards, 3 interfaces
# i) AP, ii) EM iii) Internet
OP_MODE2 = 0x2
# AP-only and Internet
# 2 cards, 2 interfaces
# i) AP, ii) Internet
OP_MODE3 = 0x3
# AP-only
# 1 card, 1 interface
# i) AP
OP_MODE4 = 0x4
# AP, Extensions w/ 1 vif
# 1 card, 2 interfaces
# i) AP, ii) Extensions
OP_MODE5 = 0x5
# AP, Extensions and Internet w/ 1 vif
# 2 cards, 3 interfaces
# i) AP, ii) Extensions, iii) Internet
OP_MODE6 = 0x6
# Advanced and WPS association 0x7
#  3 cards, 3 interfaces
#  i) AP, ii) Extensions, iii) Extensions (Managed)
OP_MODE7 = 0x7

# Advanced and WPS association w/ 1 vif support AP/Monitor 0x8
# 2 cards, 3 interfaces
# i) AP, ii) Extensions, iii) Extensions (Managed)
OP_MODE8 = 0x8

AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan

# Logging configurations
# possible values for debug levels are:
# CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
LOG_LEVEL = 'INFO'
LOG_FILEPATH = 'wifiphisher.log'
LOGGING_CONFIG = {
    'version': 1,
    # Defined the handlers
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'detailed',
            'filename': LOG_FILEPATH,
            'backupCount': 3,
        },
    },
    # fomatters for the handlers
    'formatters': {
        'detailed': {
            'format': '%(asctime)s - %(name) 32s - %(levelname)s - %(message)s'
        },
    },
    'root': {
        'level': 'DEBUG',
        'handlers': [
            'file',
        ],
    },
    "loggers": {},
    'disable_existing_loggers': False
}
CREDENTIALS_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

# Phishinghttp
VALID_POST_CONTENT_TYPE = "application/x-www-form-urlencoded"
REGEX_PWD = "password|pwd|pass"
REGEX_UNAME = "username|uname|name"

# TUI
MAIN_TUI_ATTRS = 'version essid channel ap_iface em phishinghttp args'
AP_SEL_ATTRS = 'interface mac_matcher network_manager args'

# Fourway handshake extension
CONST_A = "Pairwise key expansion"

# Rogue AP related
DENY_MACS_PATH = '/tmp/hostapd.deny'

# Known Beacons
KB_INTERVAL = 20
KB_BUCKET_SIZE = 60
KB_BEACON_CAP = 0x2105
