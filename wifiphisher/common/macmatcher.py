"""This module handles matching MAC address with vendors."""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from logging import getLogger


class MACMatcher(object):
    """Handles Organizationally Unique Identifiers (OUIs).

    The original data comes from
    http://standards.ieee.org/regauth/oui/oui.txt

    .. seealso:: http://standards.ieee.org/faqs/OUI.html
    """

    def __init__(self, vendor_file):
        # type: (Text) -> None
        """Initialize the class with all the given arguments."""
        self.logger = getLogger(__name__)
        self._vendors = dict()  # type: Dict[Text, Text]
        self._vendor_file = vendor_file

        # get the information in the vendor file
        self._get_vendor_information()

    def _get_vendor_information(self):
        # type: () -> None
        """Read and process all the data in the vendor file."""
        self.logger.debug("Parsing the vendor file")
        with open(self._vendor_file) as _file:
            for line in _file:
                # skip comment lines
                if not line.startswith("#"):
                    vendor_id, vendor_name = line.rstrip('\n').split("\t")
                    self._vendors[vendor_id] = vendor_name
                    self.logger.debug(
                        "{vendor_name} with ID {vendor_id} has been added to database".
                        format(vendor_name=vendor_name, vendor_id=vendor_id))

    def get_vendor_name(self, mac_address):
        # type: (Text) -> Text
        """Return the matched vendor name for the given MAC address.

        If the vendor is not found Unknown is returned.
        """
        # convert mac address to same format as file
        # ex. 12:34:56:78:90:AB --> 123456
        vendor_id = mac_address.replace(':', '').upper()[0:6]

        return self._vendors.get(vendor_id, "Unknown")

    def unbind(self):
        # type: () -> None
        """Discard parsed vendors.

        To save memory discard the parsed vendors. Calling
        get_vendor_name from here out will always return unkown.
        """
        self._vendors.clear()
        self.logger.debug("All vendors are removed")
