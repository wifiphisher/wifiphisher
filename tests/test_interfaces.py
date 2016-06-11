""" This module tests all the functions in the phishingpage module. """

import unittest
import mock
import wifiphisher.interfaces as interfaces


class TestNetworkAdapter(unittest.TestCase):
    """ Tests NetworkAdapter class """

    def setUp(self):
        """ Set up the tests """

        self.adapter_name = "wlan0"
        self.obj = interfaces.NetworkAdapter(self.adapter_name)

    def test_get_name(self):
        """ Test get_name method """

        message = "Failed to get correct adapter name!"
        self.assertEqual(self.obj.get_name(), self.adapter_name, message)

    def test_has_ap_mode_false(self):
        """ Test has_ap_mode method with no AP mode """

        message = "Failed to get False for adapter with no AP support!"
        self.assertFalse(self.obj.has_ap_mode(), message)

    def test_has_ap_mode_true(self):
        """ Test has_ap_mode method with AP mode available """

        # set AP support to available
        self.obj.set_ap_support(True)

        message = "Failed to get True for adapter with AP support!"
        self.assertTrue(self.obj.has_ap_mode(), message)

    def test_has_monitor_mode_false(self):
        """ Test has_monitor_mode method with no monitor mode support """

        message = "Failed to get False for adapter with no monitor support!"
        self.assertFalse(self.obj.has_monitor_mode(), message)

    def test_has_monitor_mode_true(self):
        """ Test has_monitor_mode method with monitor mode available """

        # set monitor support to available
        self.obj.set_monitor_support(True)

        message = "Failed to get True for adapter with monitor support!"
        self.assertTrue(self.obj.has_monitor_mode(), message)


class TestNetworkManager(unittest.TestCase):
    """ Tests NetworkManager class """

    def setUp(self):
        """
        Set up the tests
        """

        self.network_manager = interfaces.NetworkManager(None, None)

    @mock.patch("wifiphisher.interfaces.pyric")
    def test_check_compatibility_no_ap_no_monitor(self, mock_pyric):
        """
        Test _check_compatibility method while the interface has no AP support
        nor monitor support
        """

        # set the return value
        mock_pyric.getcard.return_value = None
        mock_pyric.devmodes.return_value = []
        mock_pyric.winterfaces.return_value = ["wlan0"]

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # call the method
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertFalse(interface.has_ap_mode())
        self.assertFalse(interface.has_monitor_mode())

    @mock.patch("wifiphisher.interfaces.pyric")
    def test_check_compatibility_has_ap_no_monitor(self, mock_pyric):
        """
        Test _check_compatibility method while the interface has AP support
        but no monitor support
        """

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_pyric.getcard.return_value = None
        mock_pyric.devmodes.return_value = ["AP"]
        mock_pyric.winterfaces.return_value = ["wlan0"]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertTrue(interface.has_ap_mode())
        self.assertFalse(interface.has_monitor_mode())

    @mock.patch("wifiphisher.interfaces.pyric")
    def test_check_compatibility_no_ap_has_monitor(self, mock_pyric):
        """
        Test _check_compatibility method while the interface doesn't have AP
        support but it has monitor support
        """

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_pyric.getcard.return_value = None
        mock_pyric.devmodes.return_value = ["monitor"]
        mock_pyric.winterfaces.return_value = ["wlan0"]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertFalse(interface.has_ap_mode())
        self.assertTrue(interface.has_monitor_mode())

    @mock.patch("wifiphisher.interfaces.pyric")
    def test_check_compatibility_has_ap_has_monitor(self, mock_pyric):
        """
        Test _check_compatibility method while the interface has AP support
        and monitor support
        """

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_pyric.getcard.return_value = None
        mock_pyric.devmodes.return_value = ["monitor", "AP"]
        mock_pyric.winterfaces.return_value = ["wlan0"]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertTrue(interface.has_ap_mode())
        self.assertTrue(interface.has_monitor_mode())

    @mock.patch("wifiphisher.interfaces.pyric")
    def test_set_interface_mode(self, mock_pyric):
        """
        Test set_interface_mode method
        """

        interface = "wlan0"

        # set return value
        mock_pyric.getcard.return_value = "test"

        # call the method
        self.network_manager.set_interface_mode(interface, "monitor")

        # check that methods are called with the right parameters
        mock_pyric.down.assert_called_with("test")
        mock_pyric.modeset.assert_called_with("test", "monitor")
        mock_pyric.up.assert_called_with("test")

    def test_find_interface_monitor_exists(self):
        """
        Test _find_interface method asking for a interface with monitor support
        that exists
        """

        # create fake interface with monitor support
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface0.set_monitor_support(True)
        self.network_manager._interfaces.append(interface0)

        actual = self.network_manager._find_interface(has_monitor_mode=True)

        self.assertEqual(actual, interface0)

    def test_find_interface_ap_exists(self):
        """
        Test _find_interface method asking for a interface with AP support
        that exists
        """

        # create fake interface with AP support
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface0.set_ap_support(True)
        self.network_manager._interfaces.append(interface0)

        actual = self.network_manager._find_interface(has_ap_mode=True)
        self.assertEqual(actual, interface0)

    def test_find_interface_AP_not_exists(self):
        """
        Test _find_interface method asking for a interface with AP support
        that does not exists
        """

        # create fake interface
        interface0 = interfaces.NetworkAdapter("wlan0")
        self.network_manager._interfaces.append(interface0)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          self.network_manager._find_interface, [True])

    def test_find_interface_no_monitor_interface(self):
        """
        Test _find_interface method asking for a interface with monitor support
        that does not exists
        """

        # create fake interface
        interface0 = interfaces.NetworkAdapter("wlan0")
        self.network_manager._interfaces.append(interface0)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          self.network_manager._find_interface, [False, True])

    def test_find_interface_automatically_no_ap_interface(self):
        """
        Test _find_interface_automatically method when no AP interfaces are
        present
        """

        # create a fake interface with monitor mode
        interface = interfaces.NetworkAdapter("wlan0")
        interface.set_monitor_support(True)
        self.network_manager._interfaces.append(interface)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          self.network_manager._find_interface_automatically)

    def test_find_interface_automatically_no_monitor_interface(self):
        """
        Test _find_interface_automatically method when no monitor interfaces
        are present
        """

        # create a fake interface with AP mode
        interface = interfaces.NetworkAdapter("wlan0")
        interface.set_ap_support(True)
        self.network_manager._interfaces.append(interface)

        self.assertRaises(interfaces.NoMonitorInterfaceFoundError,
                          self.network_manager._find_interface_automatically)

    def test_find_interface_automatically_case_0(self):
        """
        Test _find_interface_automatically method when two interfaces are given
        and both interfaces support AP and monitor mode
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # set AP and monitor support
        interface0.set_ap_support(True)
        interface0.set_monitor_support(True)
        interface1.set_ap_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        self.network_manager._interfaces.append(interface0)
        self.network_manager._interfaces.append(interface1)

        expected = (interface1, interface0)
        actual = self.network_manager._find_interface_automatically()

        self.assertEqual(actual, expected)

    def test_find_interface_automatically_case_1(self):
        """
        Test _find_interface_automatically method when two interfaces are
        given. One interfaces support AP and monitor mode while the other
        interface only supports monitor mode.
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # set AP and monitor support
        interface0.set_ap_support(True)
        interface0.set_monitor_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        self.network_manager._interfaces.append(interface0)
        self.network_manager._interfaces.append(interface1)

        expected = (interface1, interface0)
        actual = self.network_manager._find_interface_automatically()

        self.assertEqual(actual, expected)

    def test_find_interface_automatically_case_2(self):
        """
        Test _find_interface_automatically method when two interfaces are
        given. both interfaces support AP mode while only one interface
        supports AP mode.
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # set AP and monitor support
        interface0.set_ap_support(True)
        interface0.set_monitor_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        self.network_manager._interfaces.append(interface0)
        self.network_manager._interfaces.append(interface1)

        expected = (interface0, interface1)
        actual = self.network_manager._find_interface_automatically()

        self.assertEqual(actual, expected)

    def test_find_interface_automatically_case_3(self):
        """
        Test _find_interface_automatically method when two interfaces are
        given and one interfaces support AP and monitor mode while the other
        interface supports neither.
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # set AP and monitor support
        interface0.set_ap_support(True)
        interface0.set_monitor_support(True)

        # add the interfaces to the list
        self.network_manager._interfaces.append(interface0)
        self.network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.NoMonitorInterfaceFoundError,
                          self.network_manager._find_interface_automatically)

    def test_find_interface_automatically_case_4(self):
        """
        Test _find_interface_automatically method when two interfaces are
        given and both interfaces only support monitor mode.
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # set AP and monitor support
        interface0.set_monitor_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        self.network_manager._interfaces.append(interface0)
        self.network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          self.network_manager._find_interface_automatically)

    def test_get_interfaces_no_interface(self):
        """
        Test get_interfaces method with no interface present
        """

        self.assertRaises(interfaces.NotEnoughInterfacesFoundError,
                          self.network_manager.get_interfaces)

    def test_get_interfaces_valid_jamming_argument(self):
        """
        Test get_interfaces method with a valid jamming argument
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_monitor_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager("wlan0", None)
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        expected = ("wlan0", "wlan1")

        self.assertEqual(network_manager.get_interfaces(), expected)

    def test_get_interfaces_valid_jamming_argument_no_ap(self):
        """
        Test get_interfaces method with a valid jamming argument but no
        interface with AP mode
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_monitor_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager("wlan0", None)
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          network_manager.get_interfaces)

    def test_get_interfaces_invalid_jamming_argument(self):
        """
        Test get_interfaces method with a invalid jamming argument
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_monitor_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager("wlan3", None)
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.JammingInterfaceInvalidError,
                          network_manager.get_interfaces)

    def test_get_interfaces_valid_ap_argument(self):
        """
        Test get_interfaces method with a valid AP argument
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_ap_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager(None, "wlan0")
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        expected = ("wlan1", "wlan0")

        self.assertEqual(network_manager.get_interfaces(), expected)

    def test_get_interfaces_valid_ap_argument_no_monitor(self):
        """
        Test get_interfaces method with a valid AP argument but no interface
        with monitor mode
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_ap_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager(None, "wlan0")
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.NoMonitorInterfaceFoundError,
                          network_manager.get_interfaces)

    def test_get_interfaces_valid_monitor_argument_no_ap(self):
        """
        Test get_interfaces method with a valid monitor argument but no
        interface with AP mode
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_monitor_support(True)
        interface1.set_monitor_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager("wlan0", None)
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.NoApInterfaceFoundError,
                          network_manager.get_interfaces)

    def test_get_interfaces_invalid_ap_argument(self):
        """
        Test get_interfaces method with a invalid AP argument
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_ap_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager(None, "wlan3")
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        self.assertRaises(interfaces.ApInterfaceInvalidError,
                          network_manager.get_interfaces)

    def test_get_interfaces_valid_argument(self):
        """
        Test get_interfaces method with a valid arguments for both jamming and
        AP arguments
        """

        # create fake interfaces
        interface0 = interfaces.NetworkAdapter("wlan0")
        interface1 = interfaces.NetworkAdapter("wlan1")

        # make both interfaces support AP and monitor
        interface0.set_monitor_support(True)
        interface1.set_ap_support(True)

        # add the interfaces to the list
        network_manager = interfaces.NetworkManager("wlan0", "wlan1")
        network_manager._interfaces.append(interface0)
        network_manager._interfaces.append(interface1)

        expected = ("wlan0", "wlan1")
        self.assertEqual(network_manager.get_interfaces(), expected)
