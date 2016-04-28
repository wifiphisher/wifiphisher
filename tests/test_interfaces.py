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

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_exec_cmd_no_args(self, mock_sub):
        """
        Test _exec_cmd method with no arguments
        """

        # call the method
        self.network_manager._exec_cmd("test")

        # check that subprocess.Poepn is called with the right parameters
        mock_sub.Popen.assert_called_with("test", stdout=None, stderr=None)

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_exec_cmd_args(self, mock_sub):
        """
        Test _exec_cmd method with arguments
        """

        # call the method
        self.network_manager._exec_cmd("test",
                                       mock_sub.stdout, mock_sub.stderr)

        # check that subprocess.Poepn is called with the right parameters
        mock_sub.Popen.assert_called_with("test", stdout=mock_sub.stdout,
                                          stderr=mock_sub.stderr)

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_iw_cmd_valid(self, mock_sub):
        """T
        est _iw_cmd method with valid input
        """

        # set the return value and call the method
        mock_sub.Popen.return_value.communicate.return_value = ["valid", None]
        self.network_manager._iw_cmd(["some command"])

        # check that subprocess.Poepn is called with the right parameters
        mock_sub.Popen.assert_called_with(["iw", "some command"],
                                          stdout=mock_sub.PIPE,
                                          stderr=mock_sub.PIPE)

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_iw_cmd_invalid(self, mock_sub):
        """
        Test _iw_cmd method with invalid input
        """

        # set the return value
        mock_sub.Popen.return_value.communicate.return_value = [None, "error"]

        # check that the error is raised
        self.assertRaises(interfaces.IwCmdError, self.network_manager._iw_cmd,
                          ["some command"])

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_iwconfig_cmd_valid(self, mock_sub):
        """
        Test _iwconfig_cmd method with valid input
        """

        # call the method
        mock_sub.Popen.return_value.communicate.return_value = ["valid", None]
        self.network_manager._iwconfig_cmd(["valid"])

        # check that subprocess.Poepn is called with the right parameters
        mock_sub.Popen.assert_called_with(["iwconfig", "valid"],
                                          stdout=mock_sub.PIPE,
                                          stderr=mock_sub.PIPE)

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_iwconfig_cmd_invalid(self, mock_sub):
        """
        Test _iwconfig_cmd method with invalid input
        """

        # set the return value
        mock_sub.Popen.return_value.communicate.return_value = [None, "error"]

        # check that the error is raised
        self.assertRaises(interfaces.IwconfigCmdError,
                          self.network_manager._iwconfig_cmd, ["invalid"])

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_ifconfig_cmd_valid(self, mock_sub):
        """
        Test _ifconfig_cmd method with valid input
        """

        # call the method
        mock_sub.Popen.return_value.communicate.return_value = ["valid", None]
        self.network_manager._ifconfig_cmd(["valid"])

        # check that subprocess.Poepn is called with the right parameters
        mock_sub.Popen.assert_called_with(["ifconfig", "valid"],
                                          stdout=mock_sub.PIPE,
                                          stderr=mock_sub.PIPE)

    @mock.patch("wifiphisher.interfaces.subprocess")
    def test_ifconfig_cmd_invalid(self, mock_sub):
        """
        Test _ifconfig_cmd method with invalid input
        """

        # set the return value
        mock_sub.Popen.return_value.communicate.return_value = [None, "error"]

        # check that the error is raised
        self.assertRaises(interfaces.IfconfigCmdError,
                          self.network_manager._ifconfig_cmd, ["invalid"])

    @mock.patch.object(interfaces.NetworkManager, "_iw_cmd")
    def test_check_compatibility_no_ap_no_monitor(self, mock_iw):
        """
        Test _check_compatibility method while the interface has no AP support
        nor monitor support
        """

        # result to be used
        device_result = ("phy#1\n\tInterface wlan0\n\t\tifindex 4\n\t\twdev "
                         "0x100000001\n\t\taddr 00:c0:ca:81:e2:d8"
                         "\n\t\ttype managed\n")

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_iw.return_value = device_result
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertFalse(interface.has_ap_mode())
        self.assertFalse(interface.has_monitor_mode())

    @mock.patch.object(interfaces.NetworkManager, "_iw_cmd")
    def test_check_compatibility_has_ap_no_monitor(self, mock_iw):
        """
        Test _check_compatibility method while the interface has AP support
        but no monitor support
        """

        # result to be used
        device_result = ("phy#1\n\tInterface wlan0\n\t\tifindex 4\n\t\twdev "
                         "0x100000001\n\t\taddr 00:c0:ca:81:e2:d8"
                         "\n\t\ttype managed\n")
        device_info = ("\t\t * IBSS\n\t\t * managed\n\t\t * AP")

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_iw.side_effect = [device_result, device_info]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertTrue(interface.has_ap_mode())
        self.assertFalse(interface.has_monitor_mode())

    @mock.patch.object(interfaces.NetworkManager, "_iw_cmd")
    def test_check_compatibility_no_ap_has_monitor(self, mock_iw):
        """
        Test _check_compatibility method while the interface doesn't have AP
        support but it has monitor support
        """

        # result to be used
        device_result = ("phy#1\n\tInterface wlan0\n\t\tifindex 4\n\t\twdev "
                         "0x100000001\n\t\taddr 00:c0:ca:81:e2:d8"
                         "\n\t\ttype managed\n")
        device_info = ("\t\t * IBSS\n\t\t * managed\n\t\t * monitor")

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_iw.side_effect = [device_result, device_info]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertFalse(interface.has_ap_mode())
        self.assertTrue(interface.has_monitor_mode())

    @mock.patch.object(interfaces.NetworkManager, "_iw_cmd")
    def test_check_compatibility_has_ap_has_monitor(self, mock_iw):
        """
        Test _check_compatibility method while the interface has AP support
        and monitor support
        """

        # result to be used
        device_result = ("phy#1\n\tInterface wlan0\n\t\tifindex 4\n\t\twdev "
                         "0x100000001\n\t\taddr 00:c0:ca:81:e2:d8"
                         "\n\t\ttype managed\n")
        device_info = ("\t\t * IBSS\n\t\t * managed\n\t\t * monitor"
                       "\n\t\t * AP")

        # create a interface
        interface = interfaces.NetworkAdapter("wlan0")

        # set the return value and call the method
        mock_iw.side_effect = [device_result, device_info]
        self.network_manager._check_compatibility(interface)

        # check that values are correct
        self.assertTrue(interface.has_ap_mode())
        self.assertTrue(interface.has_monitor_mode())

    @mock.patch("wifiphisher.interfaces.subprocess")
    @mock.patch.object(interfaces.NetworkManager, "_ifconfig_cmd")
    def test_set_interface_mode(self, mock_sub, mock_ifconfig):
        """
        Test set_interface_mode method
        """

        # set the return value
        mock_sub.Popen.return_value.communicate.return_value = [None, None]

        interface = "wlan0"

        # call the method
        self.network_manager.set_interface_mode(interface, "monitor")
        expected = [mock.call(['wlan0', 'down']), mock.call(['wlan0', 'up'])]

        # check that methods are called with the right parameters
        mock_ifconfig.assert_has_calls(expected)
        mock_sub.assert_called_with([interface, "mode", "monitor"])

    @mock.patch.object(interfaces.NetworkManager, "_ifconfig_cmd")
    def test_find_wireless_interfaces_multiple(self, mock_ifconfig):
        """
        Test _find_wireless_interfaces method with multiple interfaces
        """

        # set the result for ifconfig call
        result = "\nwlan0: test\nlo: another\nenp: 1212"
        mock_ifconfig.return_value = result

        expected = ["wlan0"]
        actual = self.network_manager._find_wireless_interfaces()

        self.assertEqual(sorted(actual), sorted(expected))

    @mock.patch.object(interfaces.NetworkManager, "_ifconfig_cmd")
    def test_find_wireless_interfaces_no_interfaces(self, mock_ifconfig):
        """
        Test _find_wireless_interfaces method with no wireless interfaces
        """

        # set the result for ifconfig call
        result = "\nlo: another\nenp: 1212"
        mock_ifconfig.return_value = result

        expected = list()
        actual = self.network_manager._find_wireless_interfaces()

        self.assertEqual(sorted(actual), sorted(expected))

    @mock.patch.object(interfaces.NetworkManager, "_ifconfig_cmd")
    def test_find_wireless_interfaces_older_ifconfig(self, mock_ifconfig):
        """
        Test _find_wireless_interfaces method older versions of ifconfig
        """

        # set the result for ifconfig call
        result = "\nlo another\nenp 1212\nwlan0 test\nwlan2: hi"
        mock_ifconfig.return_value = result

        expected = ["wlan0", "wlan2"]
        actual = self.network_manager._find_wireless_interfaces()

        self.assertEqual(sorted(actual), sorted(expected))

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

    @unittest.skip("enable after fix")
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

    @unittest.skip("enable after fix")
    def test_find_interface_automatically_case_3(self):
        """
        Test _find_interface_automatically method when two interfaces are
        given. one interfaces support AP and monitor mode while the other
        interface supports neither AP or monitor mode.
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
