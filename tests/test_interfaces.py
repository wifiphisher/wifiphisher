# pylint: skip-file
""" This module tests the interface module """

import mock
import pytest
import pyric
import wifiphisher.common.interfaces as interfaces
import wifiphisher.common.constants as constants


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_has_mode_valid(mock_pyric):
    """ Test has_mode function when interface has mode """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.return_value = ["monitor"]

    assert interfaces.has_mode("valid", "monitor") is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_has_mode_invalid(mock_pyric):
    """ Test has_mode function when interface is invalid """
    mock_pyric.getcard.side_effect = pyric.error(19, "No such device")

    assert interfaces.has_mode("invalid", "monitor") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_has_mode_crash(mock_pyric):
    """ Test has_mode function when it fails to get the modes """
    mock_pyric.getcard.side_effect = "card"
    mock_pyric.devmodes.side_effect = pyric.error(22, "Device busy")

    assert interfaces.has_mode("valid", "monitor") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_has_mode_False(mock_pyric):
    """ Test has_mode function when interface has mode """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.return_value = ["AP"]

    assert interfaces.has_mode("interface", "monitor") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
@mock.patch("wifiphisher.common.interfaces.random")
def test_set_interface_mac_random_true(mock_random, mock_pyric):
    """
    Test set_interface_mac when not random option is given and should
    result in valid mac address change
    """
    mock_random.randint.return_value = 1
    mock_pyric.getcard.return_value = "card"
    mock_pyric.up.return_value = None
    mock_pyric.down.return_value = None
    mock_pyric.modeset.return_value = None
    mock_pyric.macget.return_value = "11:22:33:44:55:66"

    result = interfaces.set_interface_mac("interface", generate_random=True)
    assert result.status is True
    assert result.old_mac_address == "11:22:33:44:55:66"
    assert result.new_mac_address == "00:00:00:01:01:01"


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mac_bad_mac(mock_pyric):
    """
    Test set_interface_mac when the provided mac address is bad and
    should result in valid mac address change
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.up.return_value = None
    mock_pyric.down.return_value = None
    mock_pyric.modeset.return_value = None
    mock_pyric.macget.return_value = "11:22:33:44:55:66"
    mock_pyric.macset.side_effect = pyric.error(22, "Invalid mac address")
    bad_mac = "11"

    result = interfaces.set_interface_mac(
        "interface", bad_mac, generate_random=False)
    assert result.status is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mac_bad_interface_invalid(mock_pyric):
    """
    Test set_interface_mac when a bad interface is given and should
    result in no mac address change
    """
    mock_pyric.getcard.side_effect = pyric.error(1, "Bad Interface")
    mock_pyric.up.side_effect = pyric.error(1, "Bad Interface")
    mock_pyric.down.side_effect = pyric.error(1, "Bad Interface")
    mock_pyric.modeset.side_effect = pyric.error(1, "Bad Interface")
    mock_pyric.macget.side_effect = pyric.error(1, "Bad Interface")

    result = interfaces.set_interface_mac(
        "bad_interface", mac_address="11", generate_random=False)
    assert result.status is False


@mock.patch("wifiphisher.common.interfaces.pyw")
@mock.patch("wifiphisher.common.interfaces.random")
def test_set_interface_mac_not_random_true(mock_random, mock_pyric):
    """
    Test set_interface_mac when not random option is given and should
    result in valid mac address change
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.up.return_value = None
    mock_pyric.down.return_value = None
    mock_pyric.modeset.return_value = None
    mock_pyric.macget.return_value = "11:22:33:44:55:66"

    new_mac_address = "99:99:99:99:99:99"

    result = interfaces.set_interface_mac(
        "interface", mac_address=new_mac_address, generate_random=False)

    assert result.status is True
    assert result.old_mac_address == "11:22:33:44:55:66"
    assert result.new_mac_address == new_mac_address


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_turn_interface_on_sucess(mock_pyric):
    """
    test turn_interface function by turning the device on and
    returning success
    """
    mock_pyric.up.return_value = True

    assert interfaces.turn_interface("wlan", on=True, card="card") is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_turn_interface_on_fail(mock_pyric):
    """
    test turn_interface function by turning the device on and
    returning a failure
    """
    mock_pyric.up.side_effect = pyric.error(1, "test")

    assert interfaces.turn_interface("wlan", on=True, card="card") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_turn_interface_off_fail(mock_pyric):
    """
    test turn_interface function by turning the device off and
    returning a failure
    """
    mock_pyric.down.side_effect = pyric.error(1, "test")

    assert interfaces.turn_interface("wlan", on=False, card="card") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_turn_interface_off_success(mock_pyric):
    """
    test turn_interface function by turning the device on and
    returning a failure
    """
    mock_pyric.down.return_value = True

    assert interfaces.turn_interface("wlan", on=False, card="card") is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_turn_interface_card_success(mock_pyric):
    """
    test turn_interface function by providing a card object and it
    should succeed
    """
    # mock_pyric.getcard.return_value = True

    assert interfaces.turn_interface("somecard", on=False, card=None) is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_get_interface_card_valid(mock_pyric):
    """ test get_interface_card when interface is valid """
    mock_pyric.getcard.return_value = "card"

    result = interfaces.get_interface_card("valid_card")

    assert result.status is True
    assert result.card == "card"


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_get_interface_card_invalid(mock_pyric):
    """ test get_interface_card when interface is valid """
    mock_pyric.getcard.side_effect = pyric.error(1, "Bad interface")

    result = interfaces.get_interface_card("valid_card")

    assert result.status is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_valid_name_mode(mock_pyric):
    """
    Test set_interface_mode when both interface name and mode are
    valid
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.down.return_value = None
    mock_pyric.up.return_value = None
    mock_pyric.modeset.return_value = None

    assert interfaces.set_interface_mode("valid", "AP") is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_invalid_name_valid_mode(mock_pyric):
    """
    Test set_interface_mode when interface name is invalid while
    mode is valid
    """
    mock_pyric.getcard.side_effect = pyric.error(19, "No such device")

    assert interfaces.set_interface_mode("invalid", "AP") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_invalid_name_mode(mock_pyric):
    """
    Test set_interface_mode when interface name and mode are
    both invalid
    """
    mock_pyric.getcard.side_effect = pyric.error(19, "No such device")
    mock_pyric.down.side_effect = pyric.error(19, "No such device")
    mock_pyric.up.side_effect = pyric.error(19, "No such device")
    mock_pyric.modeset.side_effect = pyric.error(19, "No such device")

    assert interfaces.set_interface_mode("valid", "not_valid_mode") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_valid_name_invalid_mode(mock_pyric):
    """
    Test set_interface_mode when interface name is valid while
    mode is invalid
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.down.return_value = None
    mock_pyric.up.return_value = None
    mock_pyric.modeset.side_effect = pyric.error(22, "invalid mode")

    assert interfaces.set_interface_mode("valid", "not_valid_mode") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_invalid_card(mock_pyric):
    """
    Test set_interface_mode when provided card is invalid
    """
    mock_pyric.down.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.up.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.modeset.side_effect = pyric.error(22, "Invalid card")
    card = "card"

    assert interfaces.set_interface_mode("valid", "AP", card) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_valid_card(mock_pyric):
    """
    Test set_interface_mode when provided card is valid
    """
    mock_pyric.validcard.return_value = False
    mock_pyric.down.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.up.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.modeset.side_effect = pyric.error(22, "Invalid card")
    card = "invalid_card"

    assert interfaces.set_interface_mode("valid", "AP", card) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_turn_off_error(mock_pyric):
    """
    Test set_interface_mode when unable to turn off the device
    """
    mock_pyric.validcard.return_value = True
    mock_pyric.down.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.up.return_value = None
    mock_pyric.modeset.return_value = None
    card = "valid_card"

    assert interfaces.set_interface_mode("valid", "AP", card) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_mode_turn_on_error(mock_pyric):
    """
    Test set_interface_mode when unable to turn on the device
    """
    mock_pyric.validcard.return_value = True
    mock_pyric.down.return_value = None
    mock_pyric.up.side_effect = pyric.error(22, "Invalid card")
    mock_pyric.modeset.side_effect = None
    card = "valid_card"

    assert interfaces.set_interface_mode("valid", "AP", card) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_valid_name_channel(mock_pyric):
    """
    Test set_interface_channel when both interface name and channel are
    valid
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.validcard.return_value = True
    mock_pyric.chset.return_value = None

    assert interfaces.set_interface_channel("valid", 1) is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_valid_name_invalid_channel(mock_pyric):
    """
    Test set_interface_channel when interface name is valid while
    channel is invalid
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.validcard.return_value = True
    mock_pyric.chset.side_effect = pyric.error(-1, "Cannot convert to integer")

    assert interfaces.set_interface_channel("valid", 20) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_invalid_name_valid_channel(mock_pyric):
    """
    Test set_interface_channel when interface name is invalid while
    channel is valid
    """
    mock_pyric.getcard.side_effect = pyric.error(22, "invalid interface")
    mock_pyric.validcard.return_value = False
    mock_pyric.chset.return_value = pyric.error(22, "invalid interface")

    assert interfaces.set_interface_channel("invalid", 1) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_invalid_name_channel(mock_pyric):
    """
    Test set_interface_channel when both interface name and channel are
    invalid
    """
    mock_pyric.getcard.side_effect = pyric.error(22, "invalid interface")
    mock_pyric.validcard.return_value = False
    mock_pyric.chset.return_value = pyric.error(22, "invalid interface")

    assert interfaces.set_interface_channel("invalid", 20) is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_invalid_card(mock_pyric):
    """
    Test set_interface_channel when an invalid card is provided
    """
    mock_pyric.getcard.side_effect = pyric.error(22, "invalid interface")
    mock_pyric.validcard.return_value = False

    assert interfaces.set_interface_channel("valid", 1, card="card") is False


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_set_interface_channel_valid_card(mock_pyric):
    """
    Test set_interface_channel when a valid card is provided
    """
    mock_pyric.getcard.return_value = "card"
    mock_pyric.validcard.return_value = True
    mock_pyric.chset.return_value = None

    assert interfaces.set_interface_channel("valid", 1, card="card") is True


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_find_interface_available_physical_failed(mock_pyric):
    """
    Test find_interface function when there exists a physical interface
    which is a match
    """
    mock_pyric.winterfaces.return_value = ["ap-mon", "ap"]
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.side_effect = [["AP", "monitor"], ["AP"]]

    assert interfaces.find_interface("monitor") == (True, "ap-mon", False)


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_find_interface_none_failed(mock_pyric):
    """
    Test find_interface function when no interface exists
    """
    mock_pyric.winterfaces.return_value = []

    assert interfaces.find_interface("monitor") == (False, None, False)


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_find_interface_available_virtual_success(mock_pyric):
    """
    Test find_interface function when there exists a virtual interface
    which is a match. This uses the exclude to get the virtual
    """
    interface = "ap_mon"
    mock_pyric.winterfaces.return_value = [interface]
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.side_effect = [["AP", "monitor"]]

    assert interfaces.find_interface(
        "monitor", exclude=[interface]) == (True, interface, True)


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_find_interface_multiple_available_physical_success(mock_pyric):
    """
    Test find_interface function when there exists multiple physical
    which are matches. This uses exclude function to reduce the number
    """
    excluded = "ap-mon"
    should_select = "ap"
    mock_pyric.winterfaces.return_value = [excluded, should_select]
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.side_effect = [["AP", "monitor"], ["AP"]]

    assert interfaces.find_interface(
        "AP", exclude=[excluded]) == (True, should_select, False)


@mock.patch("wifiphisher.common.interfaces.pyw")
def test_find_interface_multiple_not_available_failed(mock_pyric):
    """
    Test find_interface function when there exists multiple physical
    interface however none of them match
    """
    mock_pyric.winterfaces.return_value = ["ap-1", "ap-2"]
    mock_pyric.getcard.return_value = "card"
    mock_pyric.devmodes.side_effect = [["AP"], ["AP"]]

    assert interfaces.find_interface("monitor") == (False, None, False)
