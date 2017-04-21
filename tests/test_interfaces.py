# pylint: skip-file
""" This module tests the interface module """

import unittest
import mock
import wifiphisher.common.interfaces as interfaces
import pyric


class TestNetworkAdapter(unittest.TestCase):
    """ Tests NetworkAdapter class """

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def setUp(self, pyw):
        """ Set up the tests """

        self.adapter_name = "wlan0"
        self.card = pyw.Card
        self.adapter = interfaces.NetworkAdapter(self.adapter_name, self.card)

    def test_name_value(self):
        """ Test the name of the interface """

        message = "Failed to get correct adapter name!"
        self.assertEqual(self.adapter.name, self.adapter_name, message)

    def test_has_ap_mode_false(self):
        """
        Test has_ap_mode variable when no AP mode support is available
        """

        message = "Failed to get False for adapter with no AP support!"
        self.assertFalse(self.adapter.has_ap_mode, message)

    def test_has_ap_mode_true(self):
        """
        Test has_ap_mode variable when AP mode support is available
        """

        # set AP support to available
        self.adapter.has_ap_mode = True

        message = "Failed to get True for adapter with AP support!"
        self.assertTrue(self.adapter.has_ap_mode, message)

    def test_has_ap_mode_set_invalid_value_error(self):
        """
        Test setting has_ap_mode variable with invalid value
        """

        with self.assertRaises(interfaces.InvalidValueError):
            self.adapter.has_ap_mode = "Invalid Value"

    def test_has_monitor_mode_false(self):
        """
        Test has_monitor_mode variable when no monitor mode support
        is available
        """

        message = "Failed to get False for adapter with no monitor support!"
        self.assertFalse(self.adapter.has_monitor_mode, message)

    def test_has_monitor_mode_true(self):
        """
        Test has_monitor_mode variable when monitor mode support is available
        """

        # set monitor support to available
        self.adapter.has_monitor_mode = True

        message = "Failed to get True for adapter with monitor support!"
        self.assertTrue(self.adapter.has_monitor_mode, message)

    def test_has_monitor_mode_set_invalid_value_error(self):
        """
        Test setting has_monitor_mode variable with invalid value
        """

        with self.assertRaises(interfaces.InvalidValueError):
            self.adapter.has_monitor_mode = "Invalid Value"

    def test_is_wireless_false(self):
        """
        Test is_wireless variable when interface is not wireless
        """

        message = "Failed to get False for adapter which is not wireless"
        self.assertFalse(self.adapter.is_wireless, message)

    def test_is_wireless_true(self):
        """ Test is_wireless variable when interface is wireless """

        # mark interface as wireless
        self.adapter.is_wireless = True

        message = "Failed to get True for adapter which is wireless"
        self.assertTrue(self.adapter.is_wireless, message)

    def test_is_wireless_set_invalid_value_error(self):
        """ Test setting is_wireless variable with invalid type"""

        with self.assertRaises(interfaces.InvalidValueError):
            self.adapter.is_wireless = "Invalid Value"

    def test_card_value(self):
        """
        Test card variable to get the pyric.Card object
        """

        message = "Failed to get the card object"
        self.assertEqual(self.card, self.adapter.card, message)


class TestInterfacePropertyDetector(unittest.TestCase):
    """ Test interface_property_detector function"""

    def setUp(self):
        """ Set up the tests """

        # setup fake card
        card = "Card"
        self.adapter = interfaces.NetworkAdapter("wlan0", card)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_has_monitor_mode(self, pyric):
        """
        Test interface_property_detector function when the interface
        has monitor mode support
        """

        pyric.devmodes.return_value = ["monitor"]

        interfaces.interface_property_detector(self.adapter)

        message = "Failed to get monitor mode support when interface has support"
        self.assertTrue(self.adapter.has_monitor_mode, message)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_no_monitor_mode(self, pyric):
        """
        Test interface_property_detector function when the interface
        doesn't have monitor mode support
        """

        pyric.devmodes.return_value = []

        interfaces.interface_property_detector(self.adapter)

        message = "Shows interface has monitor mode when it does not"
        self.assertFalse(self.adapter.has_monitor_mode, message)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_has_ap_mode(self, pyric):
        """
        Test interface_property_detector function when the interface
        has AP mode support
        """

        pyric.devmodes.return_value = ["AP"]

        interfaces.interface_property_detector(self.adapter)

        message = "Failed to get AP mode support when interface has support"
        self.assertTrue(self.adapter.has_ap_mode, message)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_no_ap_mode(self, pyric):
        """
        Test interface_property_detector function when the interface
        doesn't have AP mode support
        """

        pyric.devmodes.return_value = []

        interfaces.interface_property_detector(self.adapter)

        message = "Shows interface has AP mode when it does not"
        self.assertFalse(self.adapter.has_ap_mode, message)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_is_wireless(self, pyric):
        """
        Test interface_property_detector function when the interface
        is wireless
        """

        pyric.iswireless.return_value = True

        interfaces.interface_property_detector(self.adapter)

        message = "Failed to show interface as wireless when it is"
        self.assertTrue(self.adapter.is_wireless, message)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_interface_property_detector_is_not_wireless(self, pyric):
        """
        Test interface_property_detector function when the interface
        is not wireless
        """

        pyric.iswireless.return_value = False

        interfaces.interface_property_detector(self.adapter)

        message = "Shows interfaces is wireless when it is not"
        self.assertFalse(self.adapter.is_wireless, message)






class TestNetworkManager(unittest.TestCase):
    """ Tests NetworkManager class """

    def setUp(self):
        """
        Set up the tests
        """

        self.network_manager = interfaces.NetworkManager()

    def test_is_interface_valid_valid_none(self):
        """ Tests is_interface_valid method when interface is valid """

        interface_name = "wlan0"

        self.network_manager._name_to_object[interface_name] = None

        self.network_manager.is_interface_valid(interface_name)

    def test_is_interface_valid_no_interface_error(self):
        """
        Tests is_interface_valid method when interface is non existent
        """

        interface_name = "wlan0"

        with self.assertRaises(interfaces.InvalidInterfaceError):
            self.network_manager.is_interface_valid(interface_name)

    def test_is_interface_valid_no_ap_error(self):
        """
        Tests is_interface_valid method when interface is has no AP
        mode support but it is required
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_ap_mode = False
        self.network_manager._name_to_object[interface_name] = adapter

        with self.assertRaises(interfaces.InvalidInterfaceError):
            self.network_manager.is_interface_valid(interface_name, "AP")

    def test_is_interface_valid_has_ap_none(self):
        """
        Tests is_interface_valid method when interface is has AP
        mode support and it is required
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_ap_mode = True
        self.network_manager._name_to_object[interface_name] = adapter

        self.network_manager.is_interface_valid(interface_name, "AP")

    def test_is_interface_valid_has_monitor_none(self):
        """
        Tests is_interface_valid method when interface is has monitor
        mode support and it is required
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_monitor_mode = True
        self.network_manager._name_to_object[interface_name] = adapter

        self.network_manager.is_interface_valid(interface_name, "monitor")

    def test_is_interface_valid_no_monitor_error(self):
        """
        Tests is_interface_valid method when interface is has no monitor
        mode support and it is required
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_monitor_mode = False
        self.network_manager._name_to_object[interface_name] = adapter

        with self.assertRaises(interfaces.InvalidInterfaceError):
            self.network_manager.is_interface_valid(interface_name, "monitor")

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_set_interface_mode_interface_none(self, pyric):
        """ Test set_interface_mode method"""

        interface_name = "wlan0"
        interface_object = "Card Object"
        mode = "monitor"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter

        self.network_manager.set_interface_mode(interface_name, mode)

        pyric.down.assert_called_once_with(interface_object)
        pyric.modeset.assert_called_once_with(interface_object, mode)
        pyric.up.assert_called_once_with(interface_object)

    def test_get_interface_no_interface_error(self):
        """
        Tests get_interface method when no interface can be found
        """

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface(True)

    def test_get_interface_active_interface_error(self):
        """
        Tests get_interface method when no interface can be found
        because interface is active
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter
        self.network_manager._active.add(interface_name)

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface(has_monitor_mode=True)

    def test_get_interface_no_ap_available_error(self):
        """
        Tests get_interface method when interface with specified mode
        can't be found
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_ap_mode = False
        adapter.has_monitor_mode = False
        self.network_manager._name_to_object[interface_name] = adapter

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface(True)

    def test_get_interface_has_interface_interface(self):
        """
        Tests get_interface method when interface with specified mode
        can be found
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.has_ap_mode = True
        adapter.has_monitor_mode = True
        self.network_manager._name_to_object[interface_name] = adapter

        expected = interface_name
        actual = self.network_manager.get_interface(True, True)

        self.assertEqual(expected, actual)

    def test_get_interface_automatically_no_interface_error(self):
        """
        Tests get_interface_automatically method when no interface
        is found
        """

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface_automatically()

    def test_get_interface_automatically_monitor_only_interface_error(self):
        """
        Tests get_interface_automatically method when only monitor
        interface is found
        """

        interface_name_0 = "wlan0"
        interface_name_1 = "wlan1"
        interface_object = "Card Object"
        adapter_0 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_1 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_0.has_monitor_mode = True
        adapter_1.has_monitor_mode = True
        self.network_manager._name_to_object[interface_name_0] = adapter_0
        self.network_manager._name_to_object[interface_name_1] = adapter_1

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface_automatically()

    def test_get_interface_automatically_ap_only_interface_error(self):
        """
        Tests get_interface_automatically method when only AP interface
        is found
        """

        interface_name_0 = "wlan0"
        interface_name_1 = "wlan1"
        interface_object = "Card Object"
        adapter_0 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_1 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_0.has_ap_mode = True
        adapter_1.has_ap_mode = True
        self.network_manager._name_to_object[interface_name_0] = adapter_0
        self.network_manager._name_to_object[interface_name_1] = adapter_1

        with self.assertRaises(interfaces.InterfaceCantBeFoundError):
            self.network_manager.get_interface_automatically()

    def test_get_interface_automatically_has_interface_interfaces(self):
        """
        Tests get_interface_automatically method when two interfaces
        can be found
        """

        interface_name_0 = "wlan0"
        interface_name_1 = "wlan1"
        interface_object = "Card Object"
        adapter_0 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_1 = interfaces.NetworkAdapter(interface_name_0, interface_object)
        adapter_0.has_monitor_mode = True
        adapter_1.has_ap_mode = True
        self.network_manager._name_to_object[interface_name_0] = adapter_0
        self.network_manager._name_to_object[interface_name_1] = adapter_1

        expected = (interface_name_0, interface_name_1)
        actual = self.network_manager.get_interface_automatically()

        self.assertEqual(expected, actual)

    def test_is_interface_wired_is_wired_none(self):
        """
        Tests is_interface_wired when interface is wired
        """

        interface_name = "lan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.is_wireless = False
        self.network_manager._name_to_object[interface_name] = adapter

        self.network_manager.is_interface_wired(interface_name)

    def test_is_interface_wired_is_wireless_error(self):
        """
        Tests is_interface_wired when interface is wireless
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        adapter.is_wireless = True
        self.network_manager._name_to_object[interface_name] = adapter

        with self.assertRaises(interfaces.InvalidInternetInterfaceError):
            self.network_manager.is_interface_wired(interface_name)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_unblock_interface_is_blocked_none(self, pyric):
        """
        Tests unblock_interface when the interface is blocked
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter

        pyric.isblocked.return_value = True

        self.network_manager.unblock_interface(interface_name)

        pyric.isblocked.assert_called_once_with(interface_object)
        pyric.unblock.assert_called_once_with(interface_object)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_unblock_interface_not_blocked_none(self, pyric):
        """
        Tests unblock_interface when the interface is blocked
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter

        pyric.isblocked.return_value = False

        self.network_manager.unblock_interface(interface_name)

        pyric.isblocked.assert_called_once_with(interface_object)
        pyric.unblock.assert_not_called()

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_set_interface_channel_normal_none(self, pyric):
        """
        Tests set_interface_channel method when setting a channel
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        channel = 4
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter

        self.network_manager.set_interface_channel(interface_name, channel)

        pyric.chset.assert_called_once_with(interface_object, channel)

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_start_no_interface_none(self, pyric):
        """
        Tests start method when no interface is found
        """

        pyric.interfaces.return_value = []

        self.network_manager.start()

        expected = dict()
        actual = self.network_manager._name_to_object
        self.assertDictEqual(actual, expected)


    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_start_has_interface_none(self, pyric):
        """
        Tests start method when interface(s) has been found
        """

        interface_name = "wlan0"
        pyric.interfaces.return_value = [interface_name]

        self.network_manager.start()

        interfaces = self.network_manager._name_to_object
        self.assertIn(interface_name, interfaces)

    @mock.patch("wifiphisher.common.interfaces.pyw.getcard")
    def test_start_interface_not_compatible_none(self, pyw):
        """
        Tests start method when interface is not supported
        """

        pyw.side_effect = pyric.error(93, "Device does not support nl80211")
        self.network_manager.start()

    @mock.patch("wifiphisher.common.interfaces.pyw.getcard")
    def test_start_interface_unidentified_error_error(self, pyw):
        """
        Tests start method when an unidentified error has happened
        while getting the card
        """

        pyw.side_effect = pyric.error(2220, "This is a fake error")

        with self.assertRaises(pyric.error) as error:
            self.network_manager.start()

        the_exception = error.exception
        self.assertEqual(the_exception[0], 2220, "The error was not caught.")

    def test_on_exit_no_active_none(self):
        """
        Tests on_exit method when there are no active interfaces
        """

        self.network_manager.on_exit()

    @mock.patch("wifiphisher.common.interfaces.pyw")
    def test_on_exit_has_active_none(self, pyric):
        """
        Tests on_exit method when there are active interfaces
        """

        interface_name = "wlan0"
        interface_object = "Card Object"
        mode = "managed"
        adapter = interfaces.NetworkAdapter(interface_name, interface_object)
        self.network_manager._name_to_object[interface_name] = adapter
        self.network_manager._active.add(interface_name)

        self.network_manager.on_exit()

        pyric.modeset.assert_called_once_with(interface_object, mode)
