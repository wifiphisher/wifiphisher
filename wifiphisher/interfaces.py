"""
This module was made to handle all the interface related operations for
Wifiphisher.py
"""

import subprocess
import re


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

        message = ("We have failed to find enough wireless interfaces for the "
                   "program to run. Please ensure that you have two wireless "
                   "adapters connected to your device and they are compatible."
                   "In order to be compatible at least one of them must "
                   "supports AP mode and at least one must support monitor "
                   "mode.")
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

        message = ("We have failed to find a wireless interface which supports"
                   " AP mode. Please make sure that all the wireless adapters "
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

        message = ("We have failed to find a wireless interface which supports"
                   " monitor mode. Please make sure that all the wireless "
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

        message = ("We have failed to set the jamming interface(-jI). This is "
                   "either due to the fact that we were unable to find the "
                   "given interface in our available interfaces or the given "
                   "interface was incompatible. It is recommended to use our "
                   "automatic interface selection for better results.")
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

        message = ("We have failed to set the access point interface (-aI). "
                   "This is either due to the fact that we were unable to find"
                   " the given interface in our available interfaces or the "
                   "given interface was incompatible. It is recommended to use"
                   " our automatic interface selection for better results.")
        Exception.__init__(self, message)


class IwCmdError(Exception):
    """
    Exception class to raise in case of a error while executing _iw_cmd.
    """

    def __init__(self, error_message):
        """
        Construct the class.

        :param self: A IwCmdError object
        :param error_message: The error message to be displayed
        :type self: IwCmdError
        :type error_message: str
        :return: None
        :rtype: None
        """

        message = ("We're sorry. An error has been detected after executing "
                   "_iw_cmd method. If this is the first time you have "
                   "encountered this error you can try again. Otherwise "
                   "please report this error so we can fix it.\n" +
                   error_message)
        Exception.__init__(self, message)


class IwconfigCmdError(Exception):
    """
    Exception class to raise in case of a error while executing _iwconfig_cmd.
    """

    def __init__(self, error_message):
        """
        Construct the class.

        :param self: A IwconfigCmdError object
        :param error_message: The error message to be displayed
        :type self: IwconfigCmdError
        :type error_message: str
        :return: None
        :rtype: None
        """

        message = ("We're sorry. An error has been detected after executing "
                   "_iwconfig_cmd method. If this is the first time you have "
                   "encountered this error you can try again. Otherwise "
                   "please report this error so we can fix it.\n" +
                   error_message)
        Exception.__init__(self, message)


class IfconfigCmdError(Exception):
    """
    Exception class to raise in case of a error while executing _ifconfig_cmd.
    """

    def __init__(self, error_message):
        """
        Construct the class.

        :param self: A IfconfigCmdError object
        :param error_message: The error message to be displayed
        :type self: IfconfigCmdError
        :type error_message: str
        :return: None
        :rtype: None
        """

        message = ("We're sorry. An error has been detected after executing "
                   "_ifconfig_cmd method. If this is the first time you have "
                   "encountered this error you can try again. Otherwise "
                   "please report this error so we can fix it.\n" +
                   error_message)
        Exception.__init__(self, message)


class NetworkAdapter(object):
    """
    This class represents a newtrok interface (netwrok adapter).
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

        # setup fields
        self._name = name
        self._support_ap_mode = False
        self._support_monitor_mode = False

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

    def set_ap_support(self, availability):
        """
        Set the availability of AP mode for the interface.

        :param self: A NetworkAdapter object.
        :param availability: True if interface supports AP mode and False
            otherwise
        :type self: NetworkAdapter
        :type availability: bool
        :return: None
        :rtype: None
        """

        self._support_ap_mode = availability

    def set_monitor_support(self, availability):
        """
        Set the availability of monitor mode for the interface.

        :param self(): A NetworkAdapter object.
        :param availability: True if interface supports monitor mode and False
            otherwise
        :type self: NetworkAdapter
        :type availability: bool
        :return: None
        :rtype: None
        """

        self._support_monitor_mode = availability


class NetworkManager(object):
    """
    This class represents a network manager where it handles all the management
    for the interfaces.
    """

    def __init__(self, jamming_argument, ap_argument):
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

        # setup fields
        self._jam_argument = jamming_argument
        self._ap_argument = ap_argument
        self._interfaces = list()

        # create, add and check compatibility for each interface
        for interface in self._find_wireless_interfaces():
            interface_object = NetworkAdapter(interface)
            self._interfaces.append(interface_object)
            self._check_compatibility(interface_object)

    @staticmethod
    def _exec_cmd(command, stdout=None, stderr=None):
        """
        Return the subprocess.Popen object after executing command.

        :param command: The command to be executed
        :param stdout: Value for subprocess.Popen stdout argument.
        :param stderr: Value for subprocess.Popen stderr argument.
        :type command: list
        :type stdout: subprocess object or None
        :type stderr: subprocess object or None
        :return: The subprocess.Popen object after executing command.
        :rtype: subprocess.Popen
        """

        return subprocess.Popen(command, stdout=stdout, stderr=stderr)

    def _iw_cmd(self, arguments):
        """
        Return the output of the iw command with it's arguments.

        :param self: A NetworkManager object
        :param arguments: List of all arguments for iw command
        :type self: NetworkManager
        :type arguments: list
        :return: the output of the command
        :rtype: str
        :raises IwCmdError: If an error is produced after executing iw command
        .. seealso:: _exec_cmd
        .. warning:: "iw" should not be in arguments
        """

        # execute the command and get it's output
        command = self._exec_cmd(["iw"] + arguments, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = command.communicate()

        # raise an error in case of error detection and return stdout otherwise
        if output[1]:
            raise IwCmdError(output[1])
        else:
            return output[0]

    def _iwconfig_cmd(self, arguments):
        """
        Return the output of iwconfig command.

        :param self: A NetworkManager object
        :param arguments: List of all arguments for iwconfig command
        :type self: NetworkManager
        :type arguments: list
        :return: the output of the command
        :rtype: str
        :raises IwconfigCmdError: if an error is produced after executing
            iwconfig command
        .. seealso:: _exec_cmd
        .. warning:: "iwconfig" should not be in arguments
        """

        # execute the command and get it's output
        command = self._exec_cmd(["iwconfig"] + arguments,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = command.communicate()

        # raise an error in case of error detection and return stdout otherwise
        if output[1]:
            raise IwconfigCmdError(output[1])
        else:
            return output[0]

    def _ifconfig_cmd(self, arguments):
        """
        Return the output of ifconfig command.

        :param self: A NetworkManager object
        :param arguments: List of all arguments for ifconfig command
        :type self: NetworkManager
        :type arguments: list
        :return: the output of the command
        :rtype: str
        :raises IfconfigCmdError: if an error is produced after executing
            ifconfig command
        .. seealso:: _exec_cmd
        .. warning:: "ifconfig" should not be in arguments
        """

        # execute the command and get it's output
        command = self._exec_cmd(["ifconfig"] + arguments,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = command.communicate()

        # raise an error in case of error detection and return stdout otherwise
        if output[1]:
            raise IfconfigCmdError(output[1])
        else:
            return output[0]

    def _check_compatibility(self, interface):
        """
        Check and set the compatibility of the network adapter in regards to
        monitor mode and AP mode.

        :param self: A NetworkManager object
        :param interface: A network adapter to be checked
        :type self: NetworkManager
        :type interface: NetworkAdapter
        :return: None
        :rtype: None
        :raises IwCmdError: If an error is produced after executing iw command
        .. seealso:: _iw_cmd, _word_in_sentence, NetworkAdapter
        """

        # get a list of all the devices
        devices = self._iw_cmd(["dev"]).split("\n")

        # find the physical name of the device
        for line in range(len(devices)):
            if interface.get_name() in devices[line]:
                physical_name = devices[line-1]

        # get a list of all info about the device
        device_info = self._iw_cmd([physical_name, "info"]).split("\n")

        # determine if device supports monitor or AP mode
        for line in device_info:
            if line == "\t\t * monitor":
                interface.set_monitor_support(True)
            elif line == "\t\t * AP":
                interface.set_ap_support(True)

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

        # turn off, set the mode and turn on the interface
        self._ifconfig_cmd([interface, "down"])
        self._iwconfig_cmd([interface, "mode", mode])
        self._ifconfig_cmd([interface, "up"])

    def _find_wireless_interfaces(self):
        """
        Return a list of available wireless interfaces.

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: a list of available wireless interfaces
        :rtype: list
        :raises IfconfigCmdError: if an error is produced after executing
            ifconfig command
        """

        # initialize a list to store the wireless interfaces
        wireless_interfaces = list()

        # get the interfaces info
        interfaces_info = self._ifconfig_cmd(["-a"]).split("\n")

        # add all the wireless interfaces to the list
        for line in interfaces_info:
            # add the interface to the list if it is wireless
            result = re.match(r"(wl)\w+", line)
            if result:
                wireless_interfaces.append(result.group(0))

        return wireless_interfaces

    def get_interfaces(self):
        """
        Return a tuple containing an interface with monitor mode fallowed by an
        interface with AP mode available.

        :param self: A NetworkManager object
        :type self: NetworkManager
        :return: a tuple containing monitor interface fallowed by AP interface
        :rtype: tuple
        :raises NotEnoughInterfacesFoundError: if less than two interfaces are
            found
        :raises JammingInterfaceInvalidError: if the jamming argument is
            invalid
        :raises ApInterfaceInvalidError: if the AP argument is invalid
        .. seealso:: NetworkAdapter
        """

        monitor_interface = None
        ap_interface = None

        # raise an error in case of less than two interfaces found
        if len(self._interfaces) < 2:
            raise NotEnoughInterfacesFoundError()

        # in case of jamming argument (-jI) was supplied
        if self._jam_argument:
            for interface in self._interfaces:
                if (interface.get_name() == self._jam_argument and
                        interface.has_monitor_mode()):
                    # set the interface and remove it from the list
                    monitor_interface = interface
                    self._interfaces.remove(interface)

                    # get an interface with AP mode if ap_argument is not given
                    if not self._ap_argument:
                        ap_interface = self._find_interface(has_ap_mode=True)
                    break

            # raise an error if jamming interface given is invalid
            if not monitor_interface:
                raise JammingInterfaceInvalidError()

        # in case of AP argument (-aI) was supplied
        if self._ap_argument:
            for interface in self._interfaces:
                if (interface.get_name() == self._ap_argument and
                        interface.has_ap_mode()):
                    # set the interface and remove it from the list
                    ap_interface = interface
                    self._interfaces.remove(interface)

                    # get an interface with monitor mode if jamming_argument
                    # is not given
                    if not self._jam_argument:
                        monitor_interface =\
                                    self._find_interface(has_monitor_mode=True)
                    break

            # raise an error if AP interface given is invalid
            if not ap_interface:
                raise ApInterfaceInvalidError()

        # in case of automatic interface detection is required
        if not self._jam_argument and not self._ap_argument:
            monitor_interface, ap_interface =\
                    self._find_interface_automatically()

        return monitor_interface.get_name(), ap_interface.get_name()

    def _find_interface_automatically(self):
        """
        Find and return an interface with monitor mode support fallowed by
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

        # initialize list for comparison
        ap_available = list()
        monitor_available = list()

        # populate ap_available and monitor_available lists
        for interface in self._interfaces:
            # add all the interfaces with monitor mode
            if interface.has_monitor_mode():
                monitor_available.append(interface)

            # add all the interfaces with AP mode
            if interface.has_ap_mode():
                ap_available.append(interface)

        # raise error if no interface with AP mode is found
        if len(ap_available) == 0:
            raise NoApInterfaceFoundError()
        # raise error if no interface with monitor mode is found
        elif len(monitor_available) == 0:
            raise NoMonitorInterfaceFoundError()
        # in case of having more interfaces with monitor mode
        elif len(monitor_available) >= len(ap_available):
            # select an AP interface and remove it from available interfaces
            ap_interface = ap_available[0]
            ap_available.remove(ap_interface)

            # if the ap_interface is also in monitor_available remove it
            if ap_interface in monitor_available:
                monitor_available.remove(ap_interface)

            # select the first available interface with monitor mode
            monitor_interface = monitor_available[0]
        # in case of having more interfaces with AP mode
        else:
            # select an monitor interface and remove it from available
            # interfaces
            monitor_interface = monitor_available[0]
            monitor_available.remove(monitor_interface)

            # if the monitor_interface is also in ap_available remove it
            if monitor_interface in ap_available:
                ap_available.remove(monitor_available)

            # select the first available interface with AP mode
            ap_interface = ap_available[0]

        return monitor_interface, ap_interface

    def _find_interface(self, has_ap_mode=None, has_monitor_mode=None):
        """
        Find and return an interface depending on the arguments set. If
        has_ap_mode flag is set an interface with AP mode available might be
        returned(if it exists). If has_monitor_mode is set an interface with
        monitor mode available might be returned(if it exists).

        :param self: A NetworkManager object
        :param has_ap_mode: Value to be set if interface with AP mode is needed
        :param has_monitor_mode: Value to be set if interface with monitor
            mode is needed
        :type self: NetworkManager
        :type has_ap_mode: bool or None
        :type has_monitor_mode: bool or None
        :return: an NetworkAdapter object
        :rtype: NetworkAdapter or None
        :raises NoMonitorInterfaceFoundError: if has_monitor_mode flag is set
            but no interface with monitor mode is found
        :raises NoApInterfaceFoundError: if has_ap_mode flag is set is set but
            no interface with AP mode is found
        .. seealso:: NetworkAdapter
        """

        # find a interface which supports monitor mode and raise error if not
        # found
        if has_monitor_mode:
            for interface in self._interfaces:
                if interface.has_monitor_mode():
                    return interface
            raise NoMonitorInterfaceFoundError()
        # find a interface which supports AP mode and raise error if not found
        elif has_ap_mode:
            for interface in self._interfaces:
                if interface.has_ap_mode():
                    return interface
            raise NoApInterfaceFoundError()
