"""
Extension that sniff if there is change for WPS pbc exploitation
"""
import logging
from collections import defaultdict
import scapy.layers.dot11 as dot11
import wifiphisher.common.extensions as extensions

logger = logging.getLogger(__name__)

# define the WPS state
WPS_IDLE, WPS_ACTIVE = range(2)

class Wpspbc(object):
    """
    Handle the wps exploitation process
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A Wpspbc object
        :param data: Shared data from main engine
        :type self: Deauth
        :type data: tuple
        :return: None
        :rtype: None
        """
        self._data = data
        self._packets_to_send = defaultdict(list)
        self._wps_state = WPS_IDLE

    def process_wps_ie(self, packet):
        """
        Check if the pbc button is being pressed
        :param self: A Wpspbc object
        :param packet: A scapy.layers.RadioTap object
        :type self: Wpspbc
        :type packet: scapy.layers.RadioTap
        :return: None
        :rtype: None
        """
        elt_section = packet[dot11.Dot11Elt]
        while isinstance(elt_section, dot11.Dot11Elt):
            # check if WPS IE exists
            if elt_section.ID == 221 and\
                    elt_section.info.startswith("\x00P\xf2\x04"):
                # strip the starting 4 bytes
                wps_ie_array = [ord(val) for val in elt_section.info[4:]]
                pos = 0
                # start looping to find the WPS PBC IE
                while pos < len(wps_ie_array):
                    if wps_ie_array[pos] == 0x10 and wps_ie_array[pos+1] == 0x12:
                        self._wps_state = WPS_ACTIVE
                        extensions.IS_DEAUTH_CONT = False
                        break
                    else:
                        data_len = (wps_ie_array[pos+2] << 8) + wps_ie_array[pos+3]
                        # jump to the next data element by adding
                        # the len of type/length/data
                        pos += (2 + 2 + data_len)
                break
            elt_section = elt_section.payload

    def get_packet(self, packet):
        """
        Process the Dot11 packets

        :param self: A Wpspbc object
        :param packet: A scapy.layers.RadioTap object
        :type self: Deauth
        :type packet: scapy.layers.RadioTap
        :return: A tuple with channel list followed by packets list
        :rtype: tuple
        """
        try:
            bssid = packet.addr3
        except AttributeError:
            logger.debug("Malformed frame doesn't contain address fields")
            return self._packets_to_send

        if packet.haslayer(dot11.Dot11Beacon) and\
                bssid == self._data.target_ap_bssid:
            self.process_wps_ie(packet)
        return self._packets_to_send

    def send_output(self):
        """
        Get any relevant output message

        :param self: A Wpspbc object
        :type self: Wpspbc
        :return: A list with all the message entries
        :rtype: list
        """
        if self._wps_state == WPS_IDLE:
            return ["WPS PBC button is not yet pressed for the target AP!"]
        return ["WPS PBC button is being pressed for the target AP!"]

    def send_channels(self):
        """
        Send channes to subscribe

        :param self: A Wpspbc object
        :type self: Wpspbc
        :return: A list with all interested channels
        :rtype: list
        """
        return [self._data.target_ap_channel]
