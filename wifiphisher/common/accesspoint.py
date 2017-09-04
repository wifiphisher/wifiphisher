"""
This module was made to fork the rogue access point
"""
import os
import time
import subprocess
from roguehostapd import hostapd_controller
from roguehostapd import hostapd_constants
import wifiphisher.common.constants as constants


class AccessPoint(object):
    """
    This class forks the softAP
    """

    def __init__(self):
        """
        Setup the class with all the given arguments
        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: None
        :rtype: None
        """

        self.interface = None
        self.internet_interface = None
        self.channel = None
        self.essid = None
        self.psk = None
        # roguehostapd object
        self.hostapd_object = None

    def set_interface(self, interface):
        """
        Set the interface for the softAP
        :param self: An AccessPoint object
        :param interface: interface name
        :type self: AccessPoint
        :type interface: str
        :return: None
        :rtype: None
        """

        self.interface = interface

    def set_internet_interface(self, interface):
        """
        Set the internet interface
        :param self: An AccessPoint object
        :param interface: interface name
        :type self: AccessPoint
        :type interface: str
        :return: None
        :rtype: None
        """

        self.internet_interface = interface

    def set_channel(self, channel):
        """
        Set the channel for the softAP
        :param self: An AccessPoint object
        :param channel: channel number
        :type self: AccessPoint
        :type channel: str
        :return: None
        :rtype: None
        """

        self.channel = channel

    def set_essid(self, essid):
        """
        Set the ssid for the softAP
        :param self: An AccessPoint object
        :param essid: SSID for the softAP
        :type self: AccessPoint
        :type essid: str
        :return: None
        :rtype: None
        """

        self.essid = essid

    def set_psk(self, psk):
        """
        Set the psk for the softAP
        :param self: An AccessPoint object
        :param psk: passphrase for the softAP
        :type self: AccessPoint
        :type psk: str
        :return: None
        :rtype: None
        """

        self.psk = psk

    def start_dhcp_dns(self):
        """
        Start the dhcp server
        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: None
        :rtype: None
        """

        config = (
            'no-resolv\n'
            'interface=%s\n'
            'dhcp-range=%s\n'
        )

        with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
            dhcpconf.write(config % (self.interface, constants.DHCP_LEASE))

        with open('/tmp/dhcpd.conf', 'a+') as dhcpconf:
            if self.internet_interface:
                dhcpconf.write("server=%s" % (constants.PUBLIC_DNS,))
            else:
                dhcpconf.write("address=/#/%s" % (constants.NETWORK_GW_IP,))

        subprocess.Popen(['dnsmasq', '-C', '/tmp/dhcpd.conf'],
                         stdout=subprocess.PIPE, stderr=constants.DN)

        subprocess.Popen(['ifconfig', str(self.interface), 'mtu', '1400'],
                         stdout=constants.DN, stderr=constants.DN)

        subprocess.Popen(
            ['ifconfig', str(self.interface), 'up', constants.NETWORK_GW_IP,
             'netmask', constants.NETWORK_MASK
            ],
            stdout=constants.DN,
            stderr=constants.DN
        )
        # Give it some time to avoid "SIOCADDRT: Network is unreachable"
        time.sleep(.5)
        # Make sure that we have set the network properly.
        proc = subprocess.check_output(['ifconfig', str(self.interface)])
        if constants.NETWORK_GW_IP not in proc:
            return False
        subprocess.call(('route add -net %s netmask %s gw %s' %
                         (constants.NETWORK_IP, constants.NETWORK_MASK,
                          constants.NETWORK_GW_IP)),
                        shell=True)

    def start(self):
        """
        Start the softAP
        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: None
        :rtype: None
        """

        # create the configuration for roguehostapd
        hostapd_config = {
            "ssid": self.essid,
            "interface": self.interface,
            "channel": self.channel,
            "karma_enable": 1}
        if self.psk:
            hostapd_config['wpa_passphrase'] = self.psk

        # create the option dictionary
        hostapd_options = {'debug_level': hostapd_constants.HOSTAPD_DEBUG_OFF,
                           'mute': True,
                           "eloop_term_disable": True}

        try:
            self.hostapd_object = hostapd_controller.Hostapd()
            self.hostapd_object.start(hostapd_config, hostapd_options)
        except KeyboardInterrupt:
            raise Exception
        # when roguehostapd fail to start rollback to use the hostapd
        # on the system
        except BaseException:
            hostapd_config.pop("karma_enable", None)
            hostapd_options = {}
            hostapd_config_obj = hostapd_controller.HostapdConfig()
            hostapd_config_obj.write_configs(hostapd_config, hostapd_options)
            self.hostapd_object = subprocess.Popen(['hostapd',
                                                    hostapd_constants.\
                HOSTAPD_CONF_PATH],
                                                   stdout=constants.DN,
                                                   stderr=constants.DN)
            time.sleep(2)
            if self.hostapd_object.poll() is not None:
                raise Exception


    def on_exit(self):
        """
        Clean up the resoures when exits
        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: None
        :rtype: None
        """

        subprocess.call('pkill dnsmasq', shell=True)
        try:
            self.hostapd_object.stop()
        except BaseException:
            subprocess.call('pkill hostapd', shell=True)
            if os.path.isfile(hostapd_constants.HOSTAPD_CONF_PATH):
                os.remove(hostapd_constants.HOSTAPD_CONF_PATH)

        if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
            os.remove('/var/lib/misc/dnsmasq.leases')
        if os.path.isfile('/tmp/dhcpd.conf'):
            os.remove('/tmp/dhcpd.conf')
        # sleep 2 seconds to wait all the hostapd process is
        # killed
        time.sleep(2)
