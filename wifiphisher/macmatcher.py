#pylint: skip-file
"""
This module was made to match MAC address with vendors
"""

from constants import *


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
                    unpack = line.rstrip('\n').split('|')
                    self.mac_to_vendor[unpack[0]] = unpack

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

        if mac_address:
            # convert mac to match prefix file format
            vendor_part = mac_address.replace(':', '').upper()[0:6]

            if vendor_part in self.mac_to_vendor:
                return self.mac_to_vendor[vendor_part][1]

        return False

    def get_vendor_logo_path(self, mac_address):
        """
        Return the the full path of the logo in the filesystem
        for the given MAC address
        or empty if no match.

        :param self: A MACMatcher object
        :type self: MACMatcher
        :param mac_address: mac address represended as two
                            hexadecimal digits separated by colons
        :type mac_address: string
        :return: the full path of the logo in the filesystem
        :rtype: str
        """

        if mac_address:
            # convert mac to match prefix file format
            vendor_part = mac_address.replace(':', '').upper()[0:6]

            if vendor_part in self.mac_to_vendor and \
                    len(self.mac_to_vendor[vendor_part]) > 2:
                return LOGOS_DIR + self.mac_to_vendor[vendor_part][2]

        return None

    def unbind(self):
        """
        Unloads mac to vendor mapping from memory
        You can not use MACMatcher instance once this method is called

        :param self: A MACMatcher object
        :type self: MACMatcher

        """
        self.mac_to_vendor = {}
