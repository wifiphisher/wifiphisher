"""
This module was made to handle all the interface related operations of
the program
"""

import random
from collections import defaultdict
import logging
import pyric
import pyric.pyw as pyw
import dbus
import wifiphisher.common.constants as constants

logger = logging.getLogger("wifiphisher.interfaces")


class InvalidInterfaceError(Exception):
    """ Exception class to raise in case of a invalid interface """

    def __init__(self, interface_name, mode=None):
        """
        Construct the class

        :param self: A InvalidInterfaceError object
        :param interface_name: Name of an interface
        :type self: InvalidInterfaceError
        :type interface_name: str
        :return: None
        :rtype: None
        """

        message = "The provided interface \"{0}\" is invalid!".format(
            interface_name)

        # provide more information if mode is given
        if mode:
            message += "Interface {0} doesn't support {1} mode".format(
                interface_name, mode)

        Exception.__init__(self, message)


class InvalidMacAddressError(Exception):
    """
    Exception class to raise in case of specifying invalid mac address
    """

    def __init__(self, mac_address):
        """
        Construct the class

        :param self: A InvalidMacAddressError object
        :param mac_address: A MAC address
        :type self: InvalidMacAddressError
        :type mac_address: str
        :return: None
        :rtype: None
        """
        message = "The provided MAC address {0} is invalid".format(mac_address)
        Exception.__init__(self, message)


class InvalidValueError(Exception):
    """
    Exception class to raise in case of a invalid value is supplied
    """

    def __init__(self, value, correct_value_type):
        """
        Construct the class

        :param self: A InvalidValueError object
        :param value_type: The value supplied
        :param correct_value_type: The correct value type
        :type self: InvalidValueError
        :type value_type: any
        :type correct_value_type: any
        :return: None
        :rtype: None
        """

        value_type = type(value)

        message = ("Expected value type to be {0} while got {1}.".format(
            correct_value_type, value_type))
        Exception.__init__(self, message)


class InterfaceCantBeFoundError(Exception):
    """
    Exception class to raise in case of a invalid value is supplied
    """

    def __init__(self, interface_modes):
        """
        Construct the class

        :param self: A InterfaceCantBeFoundError object
        :param interface_modes: Modes of interface required
        :type self: InterfaceCantBeFoundError
        :type interface_modes: tuple
        :return: None
        :rtype: None
        .. note: For interface_modes the tuple should contain monitor
            mode as first argument followed by AP mode
        """

        monitor_mode = interface_modes[0]
        ap_mode = interface_modes[1]

        message = "Failed to find an interface with "

        # add appropriate mode
        if monitor_mode:
            message += "monitor"
        elif ap_mode:
            message += "AP"

        message += " mode"

        Exception.__init__(self, message)


class InterfaceManagedByNetworkManagerError(Exception):
    """
    Exception class to raise in case of NetworkManager controls the AP or deauth interface
    """

    def __init__(self, interface_name):
        """
        Construct the class.
        :param self: An InterfaceManagedByNetworkManagerError object
        :param interface_name: Name of interface
        :type self: InterfaceManagedByNetworkManagerError
        :type interface_name: str
        :return: None
        :rtype: None
        """

        message = (
            "Interface \"{0}\" is controlled by NetworkManager."
            "You need to manually set the devices that should be ignored by NetworkManager "
            "using the keyfile plugin (unmanaged-directive). For example, '[keyfile] "
            "unmanaged-devices=interface-name:\"{0}\"' needs to be added in your "
            "NetworkManager configuration file.".format(interface_name))
        Exception.__init__(self, message)


class NetworkAdapter(object):
    """ This class represents a network interface """

    def __init__(self, name, card_obj, mac_address):
        """
        Setup the class with all the given arguments

        :param self: A NetworkAdapter object
        :param name: Name of the interface
        :param card_obj: A pyric.pyw.Card object
        :param mac_address: The MAC address of interface
        :type self: NetworkAdapter
        :type name: str
        :type card_obj: pyric.pyw.Card
        :type mac_address: str
        :return: None
        :rtype: None
        """

        # Setup the fields
        self._name = name
        self._has_ap_mode = False
        self._has_monitor_mode = False
        self._is_managed_by_nm = False
        self._card = card_obj
        self._original_mac_address = mac_address
        self._current_mac_address = mac_address

    @property
    def name(self):
        """
        Return the name of the interface

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: The name of the interface
        :rtype: str
        """

        return self._name

    @property
    def is_managed_by_nm(self):
        """
        Return whether the interface controlled by NetworkManager

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: True if interface is controlled by NetworkManager
        :rtype: bool
        """
        return self._is_managed_by_nm

    @is_managed_by_nm.setter
    def is_managed_by_nm(self, value):
        """
        Set whether the interface is controlled by NetworkManager

        :param self: A NetworkAdapter object
        :param value: A value representing interface controlled by NetworkManager
        :type self: NetworkAdapter
        :type value: bool
        :return: None
        :rtype: None
        :raises InvalidValueError: When the given value is not bool
        """

        if isinstance(value, bool):
            self._is_managed_by_nm = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def has_ap_mode(self):
        """
        Return whether the interface supports AP mode

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: True if interface supports AP mode and False otherwise
        :rtype: bool
        """

        return self._has_ap_mode

    @has_ap_mode.setter
    def has_ap_mode(self, value):
        """
        Set whether the interface supports AP mode

        :param self: A NetworkAdapter object
        :param value: A value representing AP mode support
        :type self: NetworkAdapter
        :type value: bool
        :return: None
        :rtype: None
        :raises InvalidValueError: When the given value is not bool
        """

        if isinstance(value, bool):
            self._has_ap_mode = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def has_monitor_mode(self):
        """
        Return whether the interface supports monitor mode

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: True if interface supports monitor mode and False otherwise
        :rtype: bool
        """

        return self._has_monitor_mode

    @has_monitor_mode.setter
    def has_monitor_mode(self, value):
        """
        Set whether the interface supports monitor mode

        :param self: A NetworkAdapter object
        :param value: A value representing monitor mode support
        :type self: NetworkAdapter
        :type value: bool
        :return: None
        :rtype: None
        :raises InvalidValueError: When the given value is not bool
        """

        if isinstance(value, bool):
            self._has_monitor_mode = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def card(self):
        """
        Return the card object associated with the interface

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: The card object
        :rtype: pyric.pyw.Card
        """

        return self._card

    @property
    def mac_address(self):
        """
        Return the current MAC address of the interface

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: The MAC of the interface
        :rtype: str
        """

        return self._current_mac_address

    @mac_address.setter
    def mac_address(self, value):
        """
        Set the MAC address of the interface

        :param self: A NetworkAdapter object
        :param value: A value representing monitor mode support
        :type self: NetworkAdapter
        :type value: str
        :return: None
        :rtype: None
        """

        self._current_mac_address = value

    @property
    def original_mac_address(self):
        """
        Return the original MAC address of the interface

        :param self: A NetworkAdapter object
        :type self: NetworkAdapter
        :return: The original MAC of the interface
        :rtype: str
        """

        return self._original_mac_address


class NetworkManager(object):
    """
    This class represents a network manager where it handles all the management
    for the interfaces.
    """

    def __init__(self):
        """
        Setup the class with all the given arguments.

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        """

        self._name_to_object = dict()
        self._active = set()
        self._exclude_shutdown = set()
        self._internet_access_enable = False
        self._vifs_add = set()

    @property
    def internet_access_enable(self):
        """
        Return whether the -iI option is used

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        """
        return self._internet_access_enable

    @internet_access_enable.setter
    def internet_access_enable(self, value):
        """
        Set the internet access

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        """

        if isinstance(value, bool):
            self._internet_access_enable = value
        else:
            raise InvalidValueError(value, bool)

    def is_interface_valid(self, interface_name, mode=None):
        """
        Check if interface is valid

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :param mode: The mode of the interface to be checked
        :type self: NetworkManager
        :type interface_name: str
        :type mode: str
        :return: True if interface is valid
        :rtype: bool
        :raises InvalidInterfaceError: If the interface is invalid or the interface
        has been chosen in the set _active
        :raises InterfaceManagedByNetworkManagerError: If the card is managed and
                is being used as deauth/ap mode
        .. note: The available modes are monitor, AP, WPS and internet
            The internet adapter should be put in the _exclude_shutdown set
            so that it will not be shutdown after the program exits.
        """

        try:
            interface_adapter = self._name_to_object[interface_name]
        except KeyError:
            # if mode is internet and not wireless card bypass the check
            if mode == "internet":
                return True
            else:
                raise InvalidInterfaceError(interface_name)

        # add to _exclude_shutdown set if the card is internet adapter
        if mode == "internet" or mode == "WPS":
            self._exclude_shutdown.add(interface_name)
        # raise an error if interface doesn't support the mode
        if mode != "internet" and interface_adapter.is_managed_by_nm\
                and self.internet_access_enable:
            raise InterfaceManagedByNetworkManagerError(interface_name)
        if mode == "monitor" and not interface_adapter.has_monitor_mode:
            raise InvalidInterfaceError(interface_name, mode)
        elif mode == "AP" and not interface_adapter.has_ap_mode:
            raise InvalidInterfaceError(interface_name, mode)

        # raise an error if interface is already in the _active set
        if interface_name in self._active:
            raise InvalidInterfaceError(interface_name)

        self._active.add(interface_name)
        return True

    def up_interface(self, interface_name):
        """
        Equivalent to ifconfig interface_name up

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :type self: NetworkManager
        :type interface_name: str
        :return: None
        :rtype: None
        ..note: Let the pywifiphisher decide when to up the
        interface since some cards cannot up two virtual interface
        with managed mode in the same time.
        """

        card = self._name_to_object[interface_name].card
        pyw.up(card)

    def down_interface(self, interface_name):
        """
        Equivalent to ifconfig interface_name down

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :type self: NetworkManager
        :type interface_name: str
        :return: None
        :rtype: None
        """

        card = self._name_to_object[interface_name].card
        pyw.down(card)

    def set_interface_mac(self, interface_name, mac_address):
        """
        Set the specified MAC address for the interface

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :param mac_address: A MAC address
        :type self: NetworkManager
        :type interface_name: str
        :type mac_address: str
        :return: None
        :rtype: None
        .. note: This method will set the interface to managed mode
        """
        self._name_to_object[interface_name].mac_address = mac_address
        card = self._name_to_object[interface_name].card
        self.set_interface_mode(interface_name, "managed")

        self.down_interface(interface_name)
        # card must be turned off(down) before setting mac address
        try:
            pyw.macset(card, mac_address)
        # make sure to catch an invalid mac address
        except pyric.error as error:
            raise InvalidMacAddressError(mac_address)

    def get_interface_mac(self, interface_name):
        """
        Return the MAC address of the interface

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :type self: NetworkManager
        :type interface_name: str
        :return: Interface MAC address
        :rtype: str
        """

        return self._name_to_object[interface_name].mac_address

    def set_interface_mac_random(self, interface_name):
        """
        Set random MAC address for the interface

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :type self: NetworkManager
        :type interface_name: str
        :return: None
        :rtype: None
        .. note: This method will set the interface to managed mode.
            Also the first 3 octets are always 00:00:00 by default
            Only set the mac address when card is in down state
        """

        # generate a new mac address and set it to adapter's new address
        new_mac_address = generate_random_address()
        # change the mac address of adapter
        self.set_interface_mac(interface_name, new_mac_address)

    def set_interface_mode(self, interface_name, mode):
        """
        Set the specified mode for the interface

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :param mode: Mode of an interface
        :type self: NetworkManager
        :type interface_name: str
        :type mode: str
        :return: None
        :rtype: None
        .. note: Available modes are unspecified, ibss, managed, AP
            AP VLAN, wds, monitor, mesh, p2p
            Only set the mode when card is in the down state
        """

        card = self._name_to_object[interface_name].card
        self.down_interface(interface_name)
        # set interface mode between brining it down and up
        pyw.modeset(card, mode)

    def get_interface(self, has_ap_mode=False, has_monitor_mode=False):
        """
        Return the name of a valid interface with modes supplied

        :param self: A NetworkManager object
        :param has_ap_mode: AP mode support
        :param has_monitor_mode: Monitor mode support
        :type self: NetworkManager
        :type has_ap_mode: bool
        :type has_monitor_mode: bool
        :return: Name of valid interface
        :rtype: str
        .. raises InterfaceCantBeFoundError: When an interface with
            supplied modes can't be found
        .. raises InterfaceManagedByNetworkManagerError: When the chosen
        interface is managed by NetworkManager
        .. note: This method guarantees that an interface with perfect
            match will be returned if available
        """

        possible_adapters = list()
        for interface, adapter in self._name_to_object.iteritems():
            # check to make sure interface is not active and not already in the possible list
            if (interface not in self._active) and (
                    adapter not in possible_adapters):
                # in case of perfect match case
                if (adapter.has_ap_mode == has_ap_mode
                        and adapter.has_monitor_mode == has_monitor_mode):
                    possible_adapters.insert(0, adapter)

                # in case of requested AP mode and interface has AP mode (Partial match)
                elif has_ap_mode and adapter.has_ap_mode:
                    possible_adapters.append(adapter)
                # in case of requested monitor mode and interface has monitor mode (Partial match)
                elif has_monitor_mode and adapter.has_monitor_mode:
                    possible_adapters.append(adapter)

        for adapter in possible_adapters:
            if ((not adapter.is_managed_by_nm and self.internet_access_enable)
                    or (not self.internet_access_enable)):
                chosen_interface = adapter.name
                self._active.add(chosen_interface)
                return chosen_interface

        if possible_adapters:
            raise InterfaceManagedByNetworkManagerError("ALL")
        else:
            raise InterfaceCantBeFoundError((has_monitor_mode, has_ap_mode))

    def get_interface_automatically(self):
        """
        Return a name of two interfaces
        :param self: A NetworkManager object
        :param self: NetworkManager
        :return: Name of monitor interface followed by AP interface
        :rtype: tuple
        """

        monitor_interface = self.get_interface(has_monitor_mode=True)
        ap_interface = self.get_interface(has_ap_mode=True)

        return (monitor_interface, ap_interface)

    def unblock_interface(self, interface_name):
        """
        Unblock interface if it is blocked

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :type self: NetworkManager
        :type interface_name: str
        :return: None
        :rtype: None
        """

        card = self._name_to_object[interface_name].card

        # unblock card if it is blocked
        if pyw.isblocked(card):
            pyw.unblock(card)

    def set_interface_channel(self, interface_name, channel):
        """
        Set the channel for the interface

        :param self: A NetworkManager object
        :param interface_name: Name of an interface
        :param channel: A channel number
        :type self: NetworkManager
        :type interface_name: str
        :type channel: int
        :return: None
        :rtype: None
        """

        card = self._name_to_object[interface_name].card

        pyw.chset(card, channel)

    def add_virtual_interface(self, card):
        """
        Add the virtual interface to the host system
        :param self: A NetworkManager object
        :param card: A pyw.Card object
        :type self: NetworkManager
        :type card: pyw.Card
        :return name of the interface
        :rtype str
        :..note: when add the interface it is possible raising the
        pyric.error causing by adding the duplicated wlan interface
        name.
        """

        done_flag = True
        number = 0
        while done_flag:
            try:
                number += 1
                name = 'wlan' + str(number)
                pyw.down(card)
                monitor_card = pyw.devadd(card, name, 'monitor')
                done_flag = False
            # catch if wlan1 is already exist
            except pyric.error:
                pass
        self._vifs_add.add(monitor_card)
        return name

    def remove_vifs_added(self):
        """
        Remove all the added virtual interfaces
        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        """

        for card in self._vifs_add:
            pyw.devdel(card)

    def start(self):
        """
        Start the network manager

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        """

        # populate our dictionary with all the available interfaces on the system
        for interface in pyw.interfaces():
            try:
                card = pyw.getcard(interface)
                mac_address = pyw.macget(card)
                adapter = NetworkAdapter(interface, card, mac_address)
                self._name_to_object[interface] = adapter
                interface_property_detector(adapter)
            # ignore devices that are not supported(93) and no such device(19)
            except pyric.error as error:
                if error[0] == 93 or error[0] == 19:
                    pass
                else:
                    raise error

    def on_exit(self):
        """
        Perform a clean up for the class

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: None
        :rtype: None
        ..note: The cards in _exclude_shutdown will not set to the original mac address
                since these cards are not changed the mac addresses by the program.
        """

        for interface in self._active:
            if interface not in self._exclude_shutdown:
                adapter = self._name_to_object[interface]
                mac_address = adapter.original_mac_address
                self.set_interface_mac(interface, mac_address)
        # remove all the virtual added virtual interfaces
        self.remove_vifs_added()


def is_add_vif_required(args):
    """
    Return the card if only that card support both monitor and ap
    :param args: Arguemnt from pywifiphisher
    :type args: parse.args
    :return: tuple of card and is_frequency_hop_allowed
    :rtype: tuple
    """

    def get_perfect_card(phy_map_vifs, vif_score_tups):
        """
        Get the perfect card that both supports ap and monitor when we
        have only one phy interface can do that
        :param phy_map_vifs: phy number maps to the virtual interfaces
        :param vif_score_tups: list of tuple containing card and score
        :type phy_map_vifs: dict
        :type vif_score_tups: list
        :return tuple of card and single_perfect_phy_case
        :rtype: tuple
        """
        # case 1 : one phy maps to one virtual interface
        if len(phy_map_vifs) == 1 and len(phy_map_vifs.values()[0]) == 1:
            # only take the first tuple
            vif_score_tuple = vif_score_tups[0]
            card = vif_score_tuple[0]
            score = vif_score_tuple[1]
            # if this card support both monitor and AP mode
            if score == 2:
                return card, True
        # case 2 : one phy maps to multiple virtual interfaces
        # we don't need to create one more virtual interface in this case
        elif len(phy_map_vifs) == 1 and len(phy_map_vifs.values()[0]) > 1:
            return None, True
        # case 3 : we have multiple phy interfaces but only
        # one card support both monitor and AP and the other
        # ones just support the managed mode only
        elif len(phy_map_vifs) > 1:
            if vif_score_tups[0][1] == 2 and vif_score_tups[1][1] == 0:
                return vif_score_tups[0][0], True
        return None, False

    # map the phy interface to virtual interfaces
    # i.e. phy0 to wlan0
    phy_to_vifs = defaultdict(list)
    # store the phy number for the internet access
    invalid_phy_number = list()
    # record the invalid_phy_number when it is wireless card
    if args.internetinterface and pyw.iswireless(args.internetinterface):
        card = pyw.getcard(args.internetinterface)
        invalid_phy_number.append(card.phy)

    if args.wpspbc_assoc_interface:
        card = pyw.getcard(args.wpspbc_assoc_interface)
        invalid_phy_number.append(card.phy)

    # map the phy# to the virtual interface tuples
    for vif in [vif for vif in pyw.interfaces() if pyw.iswireless(vif)]:
        # excluding the card that used for internet accessing
        # setup basic card information
        score = 0
        card = pyw.getcard(vif)
        phy_number = card.phy
        if phy_number in invalid_phy_number:
            continue

        supported_modes = pyw.devmodes(card)

        if "monitor" in supported_modes:
            score += 1
        if "AP" in supported_modes:
            score += 1

        phy_to_vifs[phy_number].append((card, score))

    # each phy number map to a sublist containing (card, score)
    vif_score_tuples = [sublist[0] for sublist in phy_to_vifs.values()]
    # sort with score
    vif_score_tuples = sorted(vif_score_tuples, key=lambda tup: -tup[1])

    perfect_card, is_single_perfect_phy = get_perfect_card(
        phy_to_vifs, vif_score_tuples)

    return perfect_card, is_single_perfect_phy


def get_network_manager_objects(system_bus):
    """
    Get the required objects that implement the given interface_paths

    :param system_bus: SystemBus used to control the NetworkManager
    :type system_bus: dbus.SystemBus
    :return tuple of network manager and property accesser
    :rtype: tuple
    """

    # get the network manager proxy
    network_manager_proxy = system_bus.get_object(
        constants.NM_APP_PATH, constants.NM_MANAGER_OBJ_PATH)
    # get the network manager object that implements the NM_MANAGER_INTERFACE
    network_manager = dbus.Interface(
        network_manager_proxy,
        dbus_interface=constants.NM_MANAGER_INTERFACE_PATH)
    # get the network manager prperty accesser
    prop_accesser = dbus.Interface(
        network_manager_proxy, dbus_interface=dbus.PROPERTIES_IFACE)
    return network_manager, prop_accesser


def is_managed_by_network_manager(interface_name):
    """
    Check if the interface is managed by NetworkManager

    :param interface_name: An interface name
    :type interface_name: str
    :return if managed by NetworkManager return True
    :rtype: bool
    .. note: When the NetworkManager service is not running, using bus.get_object
        will raise the exception. It's safe to pass this exception since when
        NetworkManger doesn't run, the manage property will be unmanaged.

        We first create the network_manager_proxy first, and use it to get the
        network_manager object that implements the interface NM_MANAGER_INTERFACE_PATH.
        This network_manager object can then get all the assoicated devices, and we can
        uses these devices' paths to get the device objects. After finding the target
        device object we can then check if this device is managed by NetworkManager or not.
    """

    bus = dbus.SystemBus()
    is_managed = False
    try:
        # we only need the first returning value for network manager object
        network_manager = get_network_manager_objects(bus)[0]
        # get all the wireless devices
        devices = network_manager.GetDevices()
        for dev_obj_path in devices:
            # get the device proxy object
            device_proxy = bus.get_object(constants.NM_APP_PATH, dev_obj_path)

            # get the device object that implements the PROPERTIES_IFACE interface
            device = dbus.Interface(
                device_proxy, dbus_interface=dbus.PROPERTIES_IFACE)

            # check if the device is the target interface
            if device.Get(constants.NM_DEV_INTERFACE_PATH,
                          'Interface') == interface_name:
                is_managed = device.Get(constants.NM_DEV_INTERFACE_PATH,
                                        'Managed')
                break
    except dbus.exceptions.DBusException:
        # NetworkManager service is not running so the devices must be unmanaged
        pass
    return bool(is_managed)


def interface_property_detector(network_adapter):
    """
    Add appropriate properties of the interface such as supported modes
    and wireless type(wireless)

    :param network_adapter: A NetworkAdapter object
    :type interface_name: NetworkAdapter
    :return: None
    :rtype: None
    """

    supported_modes = pyw.devmodes(network_adapter.card)

    # check for monitor, AP and wireless mode support
    if "monitor" in supported_modes:
        network_adapter.has_monitor_mode = True
    if "AP" in supported_modes:
        network_adapter.has_ap_mode = True

    interface_name = network_adapter.name
    network_adapter.is_managed_by_nm = is_managed_by_network_manager(
        interface_name)


def is_wireless_interface(interface_name):
    """
    Check if the interface is wireless interface

    :param interface_name: Name of an interface
    :type interface_name: str
    :return: True if the interface is wireless interface
    :rtype: bool
    """

    if pyw.iswireless(interface_name):
        return True
    return False


def generate_random_address():
    """
    Make and return the randomized MAC address

    :return: A MAC address
    :rtype str
    .. warning: The first 3 octets are 00:00:00 by default
    """

    mac_address = constants.DEFAULT_OUI + ":{:02x}:{:02x}:{:02x}".format(
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    return mac_address


def does_have_mode(interface, mode):
    """
    Return whether the provided interface has the mode

    :param interface: Name of the interface
    :param mode: Mode of operation
    :type interface: str
    :type mode: str
    :return: True if interface has the mode and False otherwise
    :rtype: bool
    :Example:

        >>> does_have_mode("wlan0", "AP")
        True

        >>> does_have_mode("wlan1", "monitor")
        False
    """
    card = pyric.pyw.getcard(interface)

    return mode in pyric.pyw.devmodes(card)
