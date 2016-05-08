"""
This module was made to match MAC address with vendors
"""


class MACMatcher(object):
    """
    This class is using Organizationally Unique Identifiers (OUIs)
    in order to match MAC addresses of devices to its vendord

    See http://standards.ieee.org/faqs/OUI.html
    """
    def __init__(self, mac_prefix_file):
        """
        :param self: A MACMatcher object
        :type self: MACMatcher
        :param mac_prefix_file: path of max-prefixes file
        :type mac_prefix_file: string
        """

        self.mac_to_vendor = {}

        with open(mac_prefix_file, 'r') as prefixes_file:
            for line in prefixes_file:
                # skip comments
                if not line.startswith("#"):
                    [bssid, vendor] = line.rstrip('\n').split(' ', 1)
                    self.mac_to_vendor[bssid] = vendor

    def get_vendor_name(self, mac_address):
        """
        Return the matched vendor name for the given MAC address
        or empty if no match.

        :param self: A MACMatcher object
        :type self: MACMatcher
        :param mac_address: mac address represended as two
                            hexadecimal digits separated by colons
        :type mac_address: string
        :return: the vendor name of the device
        :rtype: str
        """

        # convert mac to match prefix file format
        vendor_part = mac_address.replace(':', '').upper()[0:6]

        if vendor_part in self.mac_to_vendor:
            return self.mac_to_vendor[vendor_part]
        else:
            return 'Unknown'

    def unbind(self):
        """
        Unloads mac to vendor mapping from memory
        You can not use MACMatcher instance once this method is called

        :param self: A MACMatcher object
        :type self: MACMatcher

        """
        self.mac_to_vendor = {}
