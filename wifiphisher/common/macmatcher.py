"""
This module was made to match MAC address with vendors
"""

import wifiphisher.common.constants as constants


class MACMatcher(object):
    """
    This class handles Organizationally Unique Identifiers (OUIs).
    The original data comes from http://standards.ieee.org/regauth/
    oui/oui.tx

    .. seealso:: http://standards.ieee.org/faqs/OUI.html
    """

    def __init__(self, mac_vendor_file):
        """
        Setup the class with all the given arguments

        :param self: A MACMatcher object
        :param mac_vendor_file: The path of the vendor file
        :type self: MACMatcher
        :type mac_vendor_file: string
        :return: None
        :rtype: None
        """

        self._mac_to_vendor = {}
        self._vendor_file = mac_vendor_file

        # get the information in the vendor file
        self._get_vendor_information()

    def _get_vendor_information(self):
        """
        Read and process all the data in the vendor file

        :param self: A MACMatcher object
        :type self: MACMatcher
        :return: None
        :rtype: None
        """

        # open the file with all the MAC addresses and
        # vendor information
        with open(self._vendor_file, 'r') as _file:
            # check every line in the file
            for line in _file:
                # skip comment lines
                if not line.startswith("#"):
                    # separate vendor and MAC addresses and add it
                    # to the dictionary
                    separated_line = line.rstrip('\n').split('|')
                    mac_identifier = separated_line[0]
                    vendor = separated_line[1]
                    logo = separated_line[2]
                    self._mac_to_vendor[mac_identifier] = (vendor, logo)

    def get_vendor_name(self, mac_address):
        """
        Return the matched vendor name for the given MAC address
        or Unknown if no match is found

        :param self: A MACMatcher object
        :param mac_address: MAC address of device
        :type self: MACMatcher
        :type mac_address: string
        :return: The vendor name of the device if MAC address is found
                 and Unknown otherwise
        :rtype: string
        """

        # Don't bother if there's no MAC
        if mac_address is None:
            return None

        # convert mac address to same format as file
        # ex. 12:34:56:78:90:AB --> 123456
        mac_identifier = mac_address.replace(':', '').upper()[0:6]

        # try to find the vendor and if not found return unknown
        try:
            vendor = self._mac_to_vendor[mac_identifier][0]
            return vendor
        except KeyError:
            return "Unknown"

    def get_vendor_logo_path(self, mac_address):
        """
        Return the the full path of the logo in the filesystem for the
        given MAC address or None if no match is found

        :param self: A MACMatcher object
        :param mac_address: MAC address of the device
        :type self: MACMatcher
        :type mac_address: string
        :return: The full path of the logo if MAC address if found and
                 None otherwise
        :rtype: string or None
        """

        # Don't bother if there's no MAC
        if mac_address is None:
            return None

        # convert mac address to same format as file
        # ex. 12:34:56:78:90:AB --> 123456
        mac_identifier = mac_address.replace(':', '').upper()[0:6]

        # check to see if vendor is available for the MAC address
        if mac_identifier in self._mac_to_vendor:
            # find the logo and it's path
            logo = self._mac_to_vendor[mac_identifier][1]
            logo_path = constants.LOGOS_DIR + logo
            # return logo name if it was provided otherwise return None
            if logo:
                return logo_path
            else:
                return None

    def unbind(self):
        """
        Unloads mac to vendor mapping from memory and therefore you can
        not use MACMatcher instance once this method is called

        :param self: A MACMatcher object
        :type self: MACMatcher
        :return: None
        :rtype: None
        """

        del self._mac_to_vendor
