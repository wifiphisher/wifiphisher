import StringIO
import mock
import wifiphisher.common.macmatcher as macmatcher


@mock.patch("__builtin__.open")
def test_parse_oui_file(mock_open):
    """
    Test parse_oui_file function with a single entry file
    """
    oui_file = "FILE LOCATION"
    identifier = "07db21"
    vendor = "HELL"

    mock_open.return_value = StringIO.StringIO("{}|{}".format(identifier, vendor))
    actual = macmatcher.parse_oui_file(oui_file)
    expected = {identifier: vendor}
    message = "Failed to parse the oui file"

    assert actual == expected, message
