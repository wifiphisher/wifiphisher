import mock
import StringIO
import wifiphisher.common.macmatcher as macmatcher


@mock.patch("__builtin__.open")
def test_parse_oui_file(mock_open):
    """
    Test parse_oui_file function with a single entry file
    """
    oui_file = "FILE LOCATION"
    identifier = "07db21"
    vendor = "HELL"
    logo = ""

    mock_open.return_value = StringIO.StringIO("{}|{}".format(identifier, vendor))
    actual = macmatcher.parse_oui_file(oui_file)
    expected = {identifier: vendor}
    message = "Failed to parse the oui file"

    assert actual == expected, message


def test_get_vendor_1():
    """
    Test get_vendor function when MAC address is known
    """
    vendor_name = "Fake Inc."
    vendors = {"112233": vendor_name}
    mac_address = "11:22:33:44:55:66"

    result = macmatcher.get_vendor(vendors, mac_address)
    message = "Failed to get correct vendor"

    assert result == vendor_name, message


def test_get_vendor_2():
    """
    Test get_vendor function when MAC address is unknown
    """
    vendor_name = "Fake Inc."
    vendors = {"112233": vendor_name}
    mac_address = "00:11:22:33:44:55"

    result = macmatcher.get_vendor(vendors, mac_address)
    message = "Failed to get correct vendor"

    assert result == "Unknown", message
