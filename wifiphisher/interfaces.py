"""
This module was made to handle all the interface related operations for
Wifiphisher.py
"""

import subprocess
import os
import re

DEVNULL = open(os.devnull, "w")


class NotEnoughInterfacesFound(Exception):
    """
    Exception class to raise in case of a finding less than enough interfaces.
    """

    def __init__(self):
        Exception.__init__(self,
                           "Not enough interfaces were found! Try again.")

class SetMonitorModeError(Exception):
    """
    Exception class to raise in case of catching any errors in
    set_interface_mode function.
    """

    def __init__(self, error_message):
        Exception.__init__(self,
                           ("An error has detected in set_interface_mode.\n" +
                            error_message))


class NoApInterfaceFound(Exception):
    """
    Exception class to raise in case of a not finding a valid AP interface.
    """

    def __init__(self):
        Exception.__init__(self, "No interface with AP mode was found!")


class NoMonitorInterfaceFound(Exception):
    """
    Exception class to raise in case of a not finding a valid monitor
    interface.
    """

    def __init__(self):
        Exception.__init__(self, "No interface with monitor mode was found!")


class JammingInterfaceInvalid(Exception):
    """
    Exception class to raise in case of a invalid jamming interface.
    """

    def __init__(self):
        Exception.__init__(self, "Invalid jamming interface (-jI) was given!")


class ApInterfaceInvalid(Exception):
    """
    Exception class to raise in case of a invalid ap interface.
    """

    def __init__(self):
        Exception.__init__(self, "Invalid AP interface (-aI) was given!")


def check_compatibility(interface):
    """
    Check the compatibility of the interface in regards to both monitor
    mode and AP mode.

    Args:
        interface (str): An interface to be checked.

    Returns:
        ((bool), (bool)): The first item indicates if the interface has monitor
                          mode and the second item indicates if AP mode is
                          available.

    Dependencies:
        word_in_sentence
    """

    # Initialize variable names
    device_name = str()
    has_monitor = bool()
    has_ap = bool()

    # run the command to get all the wireless devices
    device_command = subprocess.Popen(["iw", "dev"], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)

    # get a list of all the devices
    devices = device_command.communicate()[0].split("\n")

    # find the name of the device if available
    for line in range(len(devices)):
        if word_in_sentence(devices[line], r"\b{0}\b".format(interface)):
            device_name = devices[line-1]

    # in case the device doesn't exist return False
    if not device_name:
        return has_monitor, has_ap

    # run the command to get all the available info for device
    info_command = subprocess.Popen(["iw", device_name, "info"],
                                    stdout=subprocess.PIPE, stderr=DEVNULL)

    # list of all the info
    info = info_command.communicate()[0].split("\n")

    # check info to see if monitor or AP mode is supported
    for line in info:
        # set has_monitor to True if monitor mode is supported
        if line == "\t\t * monitor":
            has_monitor = True
        # set has_ap to True if AP mode is supported
        elif line == "\t\t * AP":
            has_ap = True

    return has_monitor, has_ap


def word_in_sentence(sentence, word):
    """
    Return whether word is in the sentence or not.

    Args:
        sentence (str): A sentence to be checked.

        word (str)    : A word to be checked against the sentence.

    Returns:
        True (bool) : If word is in the sentence.

        False (bool): If word is not in the sentence.
    """

    # search for word in the sentence
    test = re.search(word, sentence)

    # return True if the word is in the sentence and return False otherwise
    try:
        test.group(0)
        return True
    except AttributeError:
        return False


def set_interface_mode(interface, mode):
    """
    Return True if operation is setting the interface to the desired mode was
    successful, otherwise, return False and the error message provided.

    Args:
        interface (str): The name of the interface to be activated.
        mode      (str): The mode the interface should be set to. The modes are
                         [ad-hoc, managed, master, monitor, repeater,
                         secondary].

    Returns:
        ((bool), (list(str))): A boolean representing whether the operation was
                               successful or not and a list of containing
                               errors that were produced.
    """

    # turn the interface off
    down_command = subprocess.Popen(["ifconfig", interface, "down"],
                                    stdout=DEVNULL, stderr=subprocess.PIPE)

    # get any possible error
    down_error = down_command.communicate()[1]

    # raise an error if any errors were produced
    if down_error:
        raise SetMonitorModeError(down_error)

    # set the interface to managed mode
    iw_command = subprocess.Popen(["iwconfig", interface, "mode", mode],
                                  stdout=DEVNULL, stderr=subprocess.PIPE)

    # get any possible error
    iw_error = iw_command.communicate()[1]

    # raise an error if any errors were produced
    if iw_error:
        raise SetMonitorModeError(down_error)

    # turn the interface on
    on_command = subprocess.Popen(["ifconfig", interface, "up"],
                                  stdout=DEVNULL, stderr=subprocess.PIPE)

    # get any possible error
    on_error = on_command.communicate()[1]

    # raise an error if any errors were produced
    if on_error:
        raise SetMonitorModeError(on_error)


def get_wireless_interfaces():
    """
    Return a list of available wireless interfaces.

    Args:
        None.

    Returns:
        (list): A list of available wireless interfaces.
    """

    # Initialize a list to store the wireless interfaces
    wireless_interfaces = list()

    # run the command to get the interfaces
    iwconfig_command = subprocess.Popen("iwconfig", stdout=subprocess.PIPE,
                                        stderr=DEVNULL)

    # add all the wireless interfaces to the list
    for line in iwconfig_command.communicate()[0].split("\n"):
        # check if the line includes an interface
        if len(line) > 0 and line[0] != " ":
            # add the interface to the list if it is wireless
            if line.startswith("w"):
                wireless_interfaces.append(line[:line.find(" ")])

    return wireless_interfaces


def get_interfaces(jamming_argument, ap_argument):
    """
    Return a tuple containing an interface with monitor mode fallowed by an
    interface with AP mode available.

    Args:
        jamming_argument (str): The value for jamming interface
                                argument (-jI).

        ap_argument      (str): The value for ap interface argument (-aI).

    Returns:
        (str, str): A tuple containing monitor interface fallowed by
                    ap interface.

    Raises:
        NotEnoughInterfacesFound: If less than two interfaces is
                                  discovered.

        JammingInterfaceInvalid : If an invalid jamming interface (-jI) is
                                 supplied.

        ApInterfaceInvalid      : If an invalid ap interface (-aI) is
                                  supplied.

        NoApInterfaceFound      : In case of not finding a valid AP
                                  interface.

        NoMonitorInterfaceFound : In case of not finding a valid monitor
                                 interface.

    Dependencies:
        get_wireless_interfaces
        check_compatibility
        get_interface
        select_interface_automatically
    """

    # get wireless interfaces
    wireless_interfaces = get_wireless_interfaces()

    # raise an error in case of less than two interfaces found
    if len(wireless_interfaces) < 2:
        raise NotEnoughInterfacesFound()

    # in case of jamming argument (-jI) was supplied
    if jamming_argument:
        # check if the interface is both compatible and available
        if (check_compatibility(jamming_argument)[0] and
                jamming_argument in wireless_interfaces):

            # set the interface and remove it from the list
            monitor_interface = jamming_argument
            wireless_interfaces.remove(monitor_interface)

            # get an interface with ap mode if ap_argument is not given
            if not ap_argument:
                ap_interface = get_interface(wireless_interfaces, "AP")
        # raise an error in case of invalid jamming argument was supplied
        else:
            raise JammingInterfaceInvalid()

    # in case of ap argument (-aI) was supplied
    if ap_argument:
        # check if the interface is compatible and is available
        if (check_compatibility(ap_argument)[1] and
                ap_argument in wireless_interfaces):

            # set the interface and remove it from the list
            ap_interface = ap_argument
            wireless_interfaces.remove(ap_interface)

            # get an interface with monitor mode if jamming_argument is not
            # given
            if not jamming_argument:
                monitor_interface = get_interface(wireless_interfaces,
                                                  "monitor")
        # raise an error in case of invalid ap argument was supplied
        else:
            raise ApInterfaceInvalid()

    # in case of automatic interface detection is required
    if not jamming_argument and not ap_argument:
        # find the interfaces automatically
        monitor_interface, ap_interface =\
                select_interface_automatically(wireless_interfaces)

    return monitor_interface, ap_interface


def select_interface_automatically(interfaces):
    """
    Return a tuple containing monitor interface fallowed by ap interface which
    was selected automatically.

    Args:
        interfaces (list): A list of available wireless interfaces.

    Returns:
        (str, str): A tuple containing monitor interface fallowed by ap
                    interface.

    Raises:
        NoApInterfaceFound     : In case of not finding a valid AP interface.

        NoMonitorInterfaceFound: In case of not finding a valid monitor
                                 interface.

    Dependencies:
        check_compatibility
    """

    # Initialize list for comparison
    ap_available = list()
    monitor_available = list()

    # populate ap_available and monitor_available lists
    for interface in interfaces:
        # check the compatibility of interface
        compatibility = check_compatibility(interface)

        # add all the interfaces with monitor mode
        if compatibility[0]:
            monitor_available.append(interface)

        # add all the interfaces with AP mode
        if compatibility[1]:
            ap_available.append(interface)

    # raise error if no interface with ap mode is found
    if len(ap_available) == 0:
        raise NoApInterfaceFound()
    # raise error if no interface with monitor mode is found
    elif len(monitor_available) == 0:
        raise NoMonitorInterfaceFound()
    # in case of having more interfaces with monitor mode
    elif len(monitor_available) >= len(ap_available):
        # select an ap interface and remove it from available interfaces
        ap_interface = ap_available[0]
        ap_available.remove(ap_interface)

        # if the ap_interface is also in monitor_available remove it
        if ap_interface in monitor_available:
            monitor_available.remove(ap_interface)

        # select the first available interface with monitor mode
        monitor_interface = monitor_available[0]
    # in case of having more interfaces with ap mode
    else:
        # select an monitor interface and remove it from available interfaces
        monitor_interface = monitor_available[0]
        monitor_available.remove(monitor_interface)

        # if the monitor_interface is also in ap_available remove it
        if monitor_interface in ap_available:
            ap_available.remove(monitor_available)

        # select the first available interface with ap mode
        ap_interface = ap_available[0]

    return monitor_interface, ap_interface


def get_interface(interfaces, interface_type):
    """
    Return a string containing the name of the interface from interfaces
    depending on the interface_type given.

    Args:
        interfaces (list)   : A list of available wireless interfaces.

        interface_type (str): The interface type required which can have a
                              value of either 'monitor' or 'AP' for an
                              interface with monitor mode and an interface with
                              AP mode available respectively.

    Raises:
        NoMonitorInterfaceFound: If the interface_type is 'monitor' but no
                                 interfaces with monitor mode is found.

        NoApInterfaceFound     : If the interface_type is 'AP' but no interface
                                 with AP mode is found.

    Dependencies:
        check_compatibility
    """

    # Initialize ap and monitor interfaces
    monitor_interface = None
    ap_interface = None

    if interface_type == "monitor":
        for interface in interfaces:
            if check_compatibility(interface)[0]:
                monitor_interface = interface
        if not monitor_interface:
            raise NoMonitorInterfaceFound()

        return monitor_interface
    elif interface_type == "AP":
        for interface in interfaces:
            if check_compatibility(interface)[1]:
                ap_interface = interface
        if not ap_interface:
            raise NoApInterfaceFound()

        return ap_interface
