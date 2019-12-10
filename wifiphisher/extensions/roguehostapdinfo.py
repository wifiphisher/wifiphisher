"""
Extension that interacts with roguehostapd to print relevant information. For example,
information regarding automatic association attacks.
"""

from collections import defaultdict

import wifiphisher.common.constants as constants


class Roguehostapdinfo(object):
    """
    Handles for printing KARMA attack information
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A roguehostapdinfo object.
        :param data: Shared data from main engine
        :type self: roguehostapdinfo
        :type data: dictionary
        :return: None
        :rtype: None
        """
        self._data = data
        self._packets_to_send = defaultdict(list)
        self._mac2ssid_dict = defaultdict()
        self._known_beacon_ssids = self._get_known_beacon_ssids()

    def get_packet(self, packet):
        """
        :param self: A roguehostapdinfo object
        :param packet: A scapy.layers.RadioTap object
        :type self: roguehostapdinfo
        :type packet: scapy.layers.RadioTap
        :return: empty list
        :rtype: list
        """
        return self._packets_to_send

    def _get_known_beacon_ssids(self):
        """
        :param self: A roguehostapdinfo object
        :type self: roguehostapdinfo
        :return: None
        :rtype: None
        """

        known_beacons_ssids = set()
        # locate the known WLANS file
        if self._data.args.known_beacons:
            area_file = constants.KNOWN_WLANS_FILE
            with open(area_file) as _file:
                for line in _file:
                    if line.startswith("!"):
                        continue
                    essid = line.rstrip()
                    known_beacons_ssids.add(essid)
        return known_beacons_ssids

    def send_output(self):
        """
        Send the output the extension manager
        :param self: A roguehostapdinfo object.
        :type self: roguehostapdinfo
        :return: A list with the password checking information
        :rtype: list
        ..note: In each packet we ask roguehostapd whether there are victims
        associated to rogue AP
        """
        info = []
        ssid_mac_list = self._data.roguehostapd.get_karma_data()
        try:
            mac_list, ssid_list = list(zip(*ssid_mac_list))
        except ValueError:
            # incase ssid_mac_list is still empty
            mac_list = []
            ssid_list = []
        # remove the one not in the current associated list
        pop_macs = []
        for mac in self._mac2ssid_dict:
            if mac not in mac_list:
                pop_macs.append(mac)
        for key in pop_macs:
            self._mac2ssid_dict.pop(key)
        # add new associated victims to the dictionary
        for idx, mac in enumerate(mac_list):
            if mac not in self._mac2ssid_dict:
                self._mac2ssid_dict[mac] = ssid_list[idx]
        macssid_pairs = list(self._mac2ssid_dict.items())
        for mac, ssid in macssid_pairs:

            if ssid == self._data.target_ap_essid:
                outputstr = "Victim " + mac + " probed for WLAN with ESSID: '" + ssid + "' (Evil Twin)"
            elif ssid not in self._known_beacon_ssids:
                outputstr = "Victim " + mac + " probed for WLAN with ESSID: '" + ssid + "' (KARMA)"
            else:
                outputstr = "Victim " + mac + " probed for WLAN with ESSID: '" + ssid + "' (Known Beacons)"
            info.append(outputstr)
        return info

    def send_channels(self):
        """
        Send channels to subscribe
        :param self: A roguehostapdinfo object.
        :type self: roguehostapdinfo
        :return: empty list
        :rtype: list
        ..note: we don't need to send frames in this extension
        """

        return [self._data.target_ap_channel]

    def on_exit(self):
        """
        Free all the resources regarding to this module
        :param self: A roguehostapdinfo object.
        :type self: roguehostapdinfo
        :return: None
        :rtype: None
        """
        pass
