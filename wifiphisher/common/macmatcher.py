"""
This module was made to match MAC address with vendors
"""


def parse_oui_file(oui_file):
    """
    Return a dictionary containing the vendors information parsed
    from the oui_file

    :param oui_file: Location of the oui_file
    :type oui_file: str
    :return: dictionary containing parsed vendors
    :rtype: dict
    :Example:

        >>> oui_file = "somefile.txt"
        >>> my_dict = parse_oui_file(oui_file)
        >>> my_dict
        {"45a23b": "Fake Inc."}
    """

    file_handler = open(oui_file, "r")

    not_a_comment = lambda entry: not entry.startswith("#")
    split = lambda string: string.rstrip().split("|")

    vendor_information = dict(map(split, filter(not_a_comment, file_handler.readlines())))

    file_handler.close()

    return vendor_information


def get_vendor(vendors, mac_address):
    """
    Return the vendor for the specified MAC address if available
    and Unknown otherwise

    :param vendors: A dictionary containing all vendors
    :param mac_address: MAC address for the device
    :type vendors: dict
    :type mac_address: str
    :return: Vendor name or Unknown
    :rtype: str
    :Example:

        >>> mac_address = "11:22:33:44:55:66"
        >>> vendors = {"112233": "Fake Inc."}
        >>> get_vendor(vendors, mac_address)
        Fake Inc.

        >>> mac_address = "11:22:33:44:55:66"
        >>> vendors = {"112244": "Fake Inc."}
        >>> get_vendor(vendors, mac_address)
        Unknown
    """
    mac_identifier = mac_address.replace(':', '').upper()[0:6]

    return vendors.get(mac_identifier, "Unknown")
