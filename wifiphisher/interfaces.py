#pylint: skip-file
"""
This module was made to handle all the interface related operations for
Wifiphisher.py
"""

import pyric
import pyric.pyw as pyw


class NotEnoughInterfacesFoundError(Exception):
    """
    Exception class to raise in case of a finding less than enough interfaces.
    """

    def __init__(self):
        """
        Construct the class.

        :param self: A NotEnoughInterfacesFoundError object
        :type self: NotEnoughInterfacesFoundError
        :return: None
        :rtype: None
        """

        message = ("There are not enough wireless interfaces for the tool to "
                   "run! Please ensure that at least two wireless adapters "
                   "are connected to the device and they are compatible " +
                   "(drivers should support netlink). At "
                   "least one must support Master (AP) mode and another "
                   "must support Monitor mode.\n"
                   "Otherwise, you may try --nojamming option that will turn "
                   "off the deauthentication phase.")
        Exception.__init__(self, message)


class NoApInterfaceFoundError(Exception):
    """
    Exception class to raise in case of a not finding a valid AP interface.
    """

    def __init__(self):
        """
        Construct the class.

        :param self: A NoApInterfaceFoundError object
        :type self: NoApInterfaceFoundError
        :return: None
        :rtype: None
        """

        message = ("We have failed to find a wireless interface that supports"
                   " AP mode! Please make sure that all the wireless adapters "
                   "are connected and they are compatible.")
        Exception.__init__(self, message)


class NoMonitorInterfaceFoundError(Exception):
    """
    Exception class to raise in case of a not finding a valid monitor
    interface.
    """

    def __init__(self):
        """
        Construct the class.

        :param self: A NoMonitorInterfaceFoundError object
        :type self: NoMonitorInterfaceFoundError
        :return: None
        :rtype: None
        """

        message = ("We have failed to find a wireless interface that supports"
                   " monitor mode! Please make sure that all the wireless "
                   "adapters are connected and they are compatible.")
        Exception.__init__(self, message)


class JammingInterfaceInvalidError(Exception):
    """
    Exception class to raise in case of a invalid jamming interface.
    """

    def __init__(self):
        """
        Construct the class.

        :param self: A JammingInterfaceInvalidError object
        :type self: JammingInterfaceInvalidError
        :return: None
        :rtype: None
        """

        message = ("We have failed to set the jamming interface(-jI)! This is "
                   "either due to the fact that we were unable to find the "
                   "given interface in the available interfaces or the given "
                   "interface was incompatible.")
        Exception.__init__(self, message)


class ApInterfaceInvalidError(Exception):
    """
    Exception class to raise in case of a invalid ap interface.
    """

    def __init__(self):
        """
        Construct the class.

        :param self: A ApInterfaceInvalidError object
        :type self: ApInterfaceInvalidError
        :return: None
        :rtype: None
        """

        message = ("We have failed to set the access point interface (-aI)! "
                   "This is either due to the fact that we were unable to find"
                   " the given interface in the available interfaces or the "
                   "given interface was incompatible.")
        Exception.__init__(self, message)


class NetworkAdapter(object):
    """
    This class represents a newtrok interface (network adapter).
    """

    def __init__(self, name):
        """
        Setup the class with all the given arguments.

        :param self: A NetworkAdapter object
        :param name: Name of the interface
        :type self: NetworkAdapter
        :type name: str
        :return: None
        :rtype: None
        .. note: the availability of monitor mode and AP mode is set to False
            by default
        """

        # Setup the fields
        self._name = name
        self._support_ap_mode = False
        self._support_monitor_mode = False
        self.being_used = False

        # Set monitor and AP mode if card supports it
        card = pyw.getcard(name)
        modes = pyw.devmodes(card)

        if "monitor" in modes:
            self._support_monitor_mode = True
        if "AP" in modes:
            self._support_ap_mode = True

    def get_name(self):
        """
        Return the name of the interface.

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: The name of the interface
        :rtype: str
        """

        return self._name

    def has_ap_mode(self):
        """
        Return whether the interface supports AP mode.

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: True if interface supports AP mode and False otherwise
        :rtype: bool
        """

        return self._support_ap_mode

    def has_monitor_mode(self):
        """
        Return whether the interface supports monitor mode.

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: True if interface supports monitor mode and False otherwise
        :rtype: bool
        """

        return self._support_monitor_mode

    def set_channel(self, channel):
        """
        Set the device channel to the provided channel.

        :param self: A NetworkAdapter object
        :param channel: A channel number
        :type self: NetworkAdapter
        :type channel: string
        :return: None
        :rtype: None
        """
        card = pyw.getcard(self._name)
        pyw.chset(card, channel, None)


class NetworkManager(object):
    """
    This class represents a network manager where it handles all the management
    for the interfaces.
    """

    def __init__(self):
        """
        Setup the class with all the given arguments.

        :param self: A NetworkManager object
        :param jamming_argument: The jamming argument given by user
        :param ap_argument: The AP argument given by user
        :type self: NetworkManager
        :type jamming_argument: str
        :type ap_argument: str
        :return: None
        :rtype: None
        .. seealso:: NetworkAdapter
        """

        # Setup the fields
        self._interfaces = {}
        self.ap_iface = ""
        self.jam_iface = ""

        # Create, add and check compatibility for each interface
        for interface in pyw.interfaces():
            try:
                self._interfaces[interface] = NetworkAdapter(interface)
            except pyric.error as e:
                pass

    def up_ifaces(self, ifaces):
        for i in ifaces:
            card = pyw.getcard(i.get_name())
            pyw.up(card)

    def set_interface_mode(self, interface, mode):
        """
        Set the desired mode to the network interface.

        :param self: A NetworkManager object
        :param interface: A NetworkAdapter object
        :param mode: The mode the interface should be set to
        :type self: NetworkManager
        :type interface: NetworkAdapter
        :type mode: str
        :return: None
        :rtype: None
        :raises IfconfigCmdError: if an error is produced after executing
            ifconfig command
        .. note:: available modes are ad-hoc, managed, master, monitor,
            repeater, secondary
        .. seealso:: _ifconfig_cmd
        """

        # Get the card
        card = pyw.getcard(interface.get_name())

        # Turn off, set the mode and turn on the interface
        pyw.down(card)
        pyw.modeset(card, mode)
        pyw.up(card)

    def find_interface_automatically(self):
        """
        Find and return an interface with monitor mode support followed by
        an interface with AP mode support.

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: a tuple containing monitor interface fallowed by AP interface
        :rtype: tuple
        :raises NoApInterfaceFoundError: if no interface with AP mode is found
        :raises NoMonitorInterfaceFoundError: if no interface with monitor mode
            is found
        .. seealso:: NetworkAdapter
        .. warning:: The function returns NetworkAdapter objects and not str
        """

        # Raise an error in case of less than two interfaces found
        if len(self._interfaces) < 2:
            raise NotEnoughInterfacesFoundError()

        # Initialize list for comparison
        ap_available = list()
        monitor_available = list()

        # Populate ap_available and monitor_available lists
        for k, interface in self._interfaces.iteritems():
            # Add all the interfaces with monitor mode
            if interface.has_monitor_mode():
                monitor_available.append(interface)
            # Add all the interfaces with AP mode
            if interface.has_ap_mode():
                ap_available.append(interface)

        # Raise error if no interface with AP mode is found
        if len(ap_available) == 0:
            raise NoApInterfaceFoundError()
        # Raise error if no interface with monitor mode is found
        if len(monitor_available) == 0:
            raise NoMonitorInterfaceFoundError()
        # Raise error if one card is supposed to do both
        if len(monitor_available) == 1 and len(ap_available) == 1:
            if monitor_available[0] == ap_available[0]:
                raise NotEnoughInterfacesFoundError()

        # We only have one AP mode interface. We don't want to use it for
        # jamming.
        if len(monitor_available) > 1 and \
                len(ap_available) == 1 and \
                ap_available[0] in monitor_available:
            # Select an AP interface and remove it from available interfaces
            ap_interface = ap_available[0]
            ap_available.remove(ap_interface)
            # Select the first available interface with monitor mode
            for m in monitor_available:
                if m != ap_interface:
                    monitor_interface = m
            return monitor_interface, ap_interface

        # We only have one Monitor mode interface. We don't want to use it for AP.
        # Covers all other cases too
        monitor_interface = monitor_available[0]
        # Select the first available interface with monitor mode
        for a in ap_available:
            if a != monitor_interface:
                ap_interface = a

        return monitor_interface, ap_interface

    def get_jam_iface(self, interface_name):
        for k, interface in self._interfaces.iteritems():
            if k == interface_name and not interface.being_used:
                if interface.has_monitor_mode():
                    return interface
                else:
                    raise JammingInterfaceInvalidError
        raise JammingInterfaceInvalidError

    def get_ap_iface(self, interface_name=None):
        for k, interface in self._interfaces.iteritems():
            if interface_name == None:
                if interface.has_ap_mode():
                    return interface
            if k == interface_name and not interface.being_used:
                if interface.has_ap_mode():
                    return interface
                else:
                    raise ApInterfaceInvalidError
        if interface_name == None:
            raise NoApInterfaceFoundError
        raise ApInterfaceInvalidError

    def set_internet_iface(self, iface):
        if pyw.iswireless(iface):
            raise Exception
        self.internet_iface = iface

    def set_ap_iface(self, iface):
        self.ap_iface = iface
        iface_obj = self._interfaces[iface]
        iface_obj.being_used = True
        self._interfaces[iface] = iface_obj

    def set_jam_iface(self, iface):
        self.jam_iface = iface
        iface_obj = self._interfaces[iface]
        iface_obj.being_used = True
        self._interfaces[iface] = iface_obj

    def reset_ifaces_to_managed(self):
        for k, i in self._interfaces.iteritems():
            if i.being_used:
                self.set_interface_mode(i, "managed")
