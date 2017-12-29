"""
This module handles all the operations regarding locating all the
available access points
"""

from __future__ import division
import threading
import time
import logging
import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants

logger = logging.getLogger(__name__)


class AccessPoint(object):
    """ This class represents an access point """

    def __init__(self, ssid, bssid, channel, encryption, capture_file=False):
        """
        Setup the class with all the given arguments

        :param self: An AccessPoint object
        :param ssid: The name of the access point
        :param bssid: The MAC address of the access point
        :param channel: The channel number of the access point
        :param encryption: The encryption type of the access point
        :type self: AccessPoint
        :type ssid: string
        :type bssid: string
        :type channel: string
        :type encryption: string
        """

        self._name = ssid
        self._mac_address = bssid
        self._channel = channel
        self._encryption = encryption
        self._signal_strength = None
        self._clients = set()

        if capture_file:
            with open(capture_file, "a") as f:
                f.write(bssid + " " + ssid + "\n")

    def get_name(self):
        """
        Return the name(ESSID) of the access point

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: Name of the access point
        :rtype: string
        """

        return self._name

    def get_mac_address(self):
        """
        Return the MAC address(BSSID) of the access point

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: MAC address of the access point
        :rtype: string
        """

        return self._mac_address

    def get_channel(self):
        """
        Return the channel of the access point

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: Channel of the access point
        :rtype: string
        """

        return self._channel

    def get_encryption(self):
        """
        Return the encryption type of the access point

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: Encryption type of the access point
        :rtype: string
        """

        return self._encryption

    def get_signal_strength(self):
        """
        Return the access point's signal strength

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: Access point's singnal strength
        :rtype: string
        """

        return self._signal_strength

    def set_signal_strength(self, power):
        """
        Set the access point's sinnal strength

        :param self: An AccessPoint object
        :param power: The signal strength of access point
        :type self: AccessPoint
        :type power: string
        :return: None
        :rtype: None
        """

        self._signal_strength = power

    def add_client(self, client):
        """
        Adds the client if client is new

        :param self: An AccessPoint object
        :param client: A client's MAC address
        :type self: AccessPoint
        :type client: string
        :return: None
        :rtype: None
        """

        self._clients.add(client)

    def get_number_connected_clients(self):
        """
        Return the number of connected clients to get access point

        :param self: An AccessPoint object
        :type self: AccessPoint
        :return: Number of connected clients
        :rtype: int
        """

        return len(self._clients)


class AccessPointFinder(object):
    """ This class finds all the available access point """

    def __init__(self, ap_interface, network_manager):
        """
        Setup the class with all the given arguments

        :param self: An AccessPointFinder object
        :param ap_interface: A NetworkAdapter object
        :param network_manager: A NetworkManager object
        :type self: AccessPointFinder
        :type ap_interface: str
        :type: network_manager: NetworkManager
        :return: None
        :rtype: None
        """

        self._interface = ap_interface
        self._observed_access_points = list()
        self._capture_file = False
        self._should_continue = True
        self._hidden_networks = list()
        self._sniff_packets_thread = None
        self._channel_hop_thread = None
        self._network_manager = network_manager

        # filter used to remove non-client addresses
        self._non_client_addresses = constants.NON_CLIENT_ADDRESSES

    def _process_packets(self, packet):
        """
        Process a RadioTap packet to find access points

        :param self: An AccessPointFinder object
        :param packet: A scapy.layers.RadioTap object
        :type self: AccessPointFinder
        :type packet: scapy.layers.RadioTap
        :return: None
        :rtype: None
        """

        # check the type of the packet
        if packet.haslayer(dot11.Dot11Beacon):
            # check if the packet has info field to prevent processing
            # malform beacon
            if hasattr(packet.payload, 'info'):
                # if the packet has no info (hidden ap) add MAC address of it
                # to the list
                # note \00 used for when ap is hidden and shows only the length
                # of the name. see issue #506
                if not packet.info or "\00" in packet.info:
                    if packet.addr3 not in self._hidden_networks:
                        self._hidden_networks.append(packet.addr3)
                # otherwise get it's name and encryption
                else:
                    self._create_ap_with_info(packet)

        # if packet is a probe response and it's hidden add the
        # access point
        elif packet.haslayer(dot11.Dot11ProbeResp):
            if packet.addr3 in self._hidden_networks:
                self._create_ap_with_info(packet)

        # check to see if it is a client of access points
        elif packet.haslayer(dot11.Dot11):
            self._find_clients(packet)

    def _parse_rssi(self, packet):
        """
        Parse the rssi info from the packet

        :param self: An AccessPointFinder object
        :param packet: A scapy.layers.RadioTap object
        :type self: AccessPointFinder
        :type packet: scapy.layers.RadioTap
        :return: rssi
        :rtype: int
        """
        tmp = ord(packet.notdecoded[-4:-3])
        tmp1 = ord(packet.notdecoded[-2:-1])
        rssi = -(256 - max(tmp, tmp1))
        return rssi

    def _create_ap_with_info(self, packet):
        """
        Create and add an access point using the extracted information

        :param self: An AccessPointFinder object
        :param packet: A scapy.layers.RadioTap object
        :type self: AccessPointFinder
        :type packet: scapy.layers.RadioTap
        :return: None
        :rtype: None
        :note: return when the frame is malformed or the channel is not
        in the 2G channel list
        """

        elt_section = packet[dot11.Dot11Elt]
        try:
            channel = str(ord(packet[dot11.Dot11Elt][2].info))
            if int(channel) not in constants.ALL_2G_CHANNELS:
                return
        except (TypeError, IndexError):
            return

        mac_address = packet.addr3
        name = None
        encryption_type = None
        non_decodable_name = "<contains non-printable chars>"

        # find the signal strength
        rssi = self._parse_rssi(packet)
        new_signal_strength = self._calculate_signal_strength(rssi)

        # get the name of the access point
        # if the name is no utf8 compatible use pre set name
        try:
            name = elt_section.info.decode("utf8")
        except UnicodeDecodeError:
            name = non_decodable_name

        # just update signal strength in case of discovered
        # access point
        for access_point in self._observed_access_points:
            if mac_address == access_point.get_mac_address():
                # find the current and calculate the difference
                current_signal_strength = access_point.get_signal_strength()
                signal_strength_difference = new_signal_strength -\
                    current_signal_strength

                # update signal strength if more than 5% difference
                if signal_strength_difference > 5:
                    access_point.set_signal_strength(new_signal_strength)

                return None

        # get encryption type
        encryption_type = self._find_encryption_type(packet)

        # with all the information gathered create and add the
        # access point
        access_point = AccessPoint(
            name,
            mac_address,
            channel,
            encryption_type,
            capture_file=self._capture_file)
        access_point.set_signal_strength(new_signal_strength)
        self._observed_access_points.append(access_point)

    def _find_encryption_type(self, packet):
        """
        Return the encryption type of the access point

        :param self: An AccessPointFinder object
        :param packet: A scapy.layers.RadioTap object
        :type self: AccessPointFinder
        :type packet: scapy.layers.RadioTap
        :return: encryption type of the access point
        :rtype: string
        .. note: Possible return values are WPA2, WPA, WEP and OPEN
        """

        encryption_info = packet.sprintf("%Dot11Beacon.cap%")
        elt_section = packet[dot11.Dot11Elt]
        encryption_type = None
        is_wps = False

        # extract information from packet
        while isinstance(elt_section, dot11.Dot11Elt):
            # check if encryption type is WPA2
            if elt_section.ID == 48:
                encryption_type = "WPA2"

            # check if encryption type is WPA
            elif elt_section.ID == 221 and\
                    elt_section.info.startswith("\x00P\xf2\x01\x01\x00"):
                encryption_type = "WPA"
            # check if WPS IE exists
            if elt_section.ID == 221 and\
                    elt_section.info.startswith("\x00P\xf2\x04"):
                is_wps = True
            # break if wps and security is found
            if encryption_type and is_wps:
                break

            # break down the packet
            elt_section = elt_section.payload

        # check to see if encryption type is either WEP or OPEN
        if not encryption_type:
            if "privacy" in encryption_info:
                encryption_type = "WEP"
            else:
                encryption_type = "OPEN"

        if encryption_type != "WEP" and is_wps:
            encryption_type += "/WPS"

        return encryption_type

    def _sniff_packets(self):
        """
        Sniff packets one at a time until otherwise set

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: None
        :rtype: None
        """

        # continue to find clients until otherwise told
        while self._should_continue:
            dot11.sniff(
                iface=self._interface,
                prn=self._process_packets,
                count=1,
                store=0)

    def capture_aps(self):
        self._capture_file = constants.LOCS_DIR + "area_" +\
            time.strftime("%Y%m%d_%H%M%S")
        logger.info("Create lure10-capture file %s", self._capture_file)

    def find_all_access_points(self):
        """
        Find all the visible and hidden access points

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: An tuple of sniff and channel hop threads
        :rtype: tuple
        """

        # start finding access points in a separate thread
        self._sniff_packets_thread = threading.Thread(
            target=self._sniff_packets)
        self._sniff_packets_thread.start()

        # start channel hopping in a separate thread
        self._channel_hop_thread = threading.Thread(target=self._channel_hop)
        self._channel_hop_thread.start()

    def stop_finding_access_points(self):
        """
        Stops looking for access points.

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: None
        :rtype: None
        """

        self._should_continue = False
        # wait for 10 second to join the threads
        self._channel_hop_thread.join(10)
        self._sniff_packets_thread.join(10)

    def get_all_access_points(self):
        """
        Return a list of all access points

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: list of access points
        :rtype: list
        .. note: A list of AccessPoint objects will be returned
        """

        return self._observed_access_points

    def _channel_hop(self):
        """
        Change the interface's channel every three seconds

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: None
        :rtype: None
        .. note: The channel range is between 1 to 13
        """

        # if the stop flag not set, change the channel
        while self._should_continue:
            for channel in constants.ALL_2G_CHANNELS:
                # added this check to reduce shutdown time
                if self._should_continue:
                    self._network_manager.set_interface_channel(
                        self._interface, channel)
                    time.sleep(3)
                else:
                    break

    def _calculate_signal_strength(self, rssi):
        """
        calculate the signal strength of access point

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: Signal strength of access point
        :rtype: int
        """

        # calculate signal strength based on rssi value
        if rssi <= -100:
            signal_strength = 0
        elif rssi >= -50:
            signal_strength = 100
        else:
            signal_strength = 2 * (rssi + 100)

        return signal_strength

    def _find_clients(self, packet):
        """
        Find and add if a client is discovered

        :param self: An AccessPointFinder object
        :param packet: A scapy.layers.RadioTap object
        :type self: AccessPointFinder
        :type packet: scapy.layers.RadioTap
        :return: None
        :rtype: None
        """

        # find sender and receiver
        receiver = packet.addr1
        sender = packet.addr2

        # only continue if both addresses are available
        if sender and receiver:
            # find sender and receiver first half of MAC address
            receiver_identifier = receiver[:8]
            sender_identifier = sender[:8]

        else:
            return None

        # if a valid address is provided
        if (receiver_identifier, sender_identifier) not in\
                self._non_client_addresses:

            # if discovered access point is either sending or receving
            # add client if it's mac address is not in the MAC filter
            for access_point in self._observed_access_points:
                # get the access point MAC address
                access_point_mac = access_point.get_mac_address()

                # in case access point is the reciever
                # add sender as client
                if access_point_mac == receiver:
                    access_point.add_client(sender)

                # in case access point is the sender add reciever
                # as client
                elif access_point_mac == sender:
                    access_point.add_client(receiver)

    def get_sorted_access_points(self):
        """
        Return all access points sorted based on signal strength

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: None
        :rtype: None
        """

        # sort access points in descending order based on
        # signal strength
        sorted_access_points = sorted(
            self._observed_access_points,
            key=lambda ap: ap.get_signal_strength(),
            reverse=True)

        return sorted_access_points
