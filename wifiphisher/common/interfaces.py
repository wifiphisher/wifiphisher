"""This module was made to handle all the interface related operations of
the program
"""

import random
import collections
import subprocess
import logging
from typing import NamedTuple, Tuple, Any, List, Optional
import pyric
import pyric.pyw as pyw
import wifiphisher.common.constants as constants

LOGGER = logging.getLogger("wifiphisher.interfaces")

MacResult = NamedTuple("MacResult",
                       [("status", bool), ("old_mac_address", str),
                        ("new_mac_address", str)])
FindResult = NamedTuple("FindResult", [("name", str), ("is_virtual", bool)])
TwoInterfaceResult = NamedTuple(
    "TwoInterfaceResult", [("status", bool), ("monitor_interface", str),
                           ("ap_interface", str), ("monitor_virtual", bool),
                           ("ap_virtual", bool)])


def set_interface_mac(interface_name, mac_address="", generate_random=True):
    # type: (str, str, bool) -> MacResult
    """ Set interface MAC address.

    Set the specified MAC address for the interface if generate_random is
    False otherwise set a random MAC address to the interface.

    .. note: This method will set the interface to managed mode.

    Example:
        >>> set_interface_mac("valid", mac_address="11:22:33:44:55:66",
                              generate_random=False)
        MacResult(status=True, old_mac_address="12:34:56:78:90:11",
                   new_mac_address="11:22:33:44:55:66")

        >>> set_interface_mac("invalid", mac_address="11:22:33:44:55:66",
                              generate_random=False)
        MacResult(status=False, old_mac_address="00:00:00:00:00:00",
                  new_mac_address="11:22:33:44:55:66")
    """
    status = False
    old_mac_address = "00:00:00:00:00:00"
    card = get_interface_card(interface_name)

    if generate_random:
        new_mac_address = "00:00:00:{:02x}:{:02x}:{:02x}".format(
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255))
    else:
        new_mac_address = mac_address

    if card and set_interface_mode(interface_name, "managed", card):
        try:
            old_mac_address = pyw.macget(card)
            pyw.macset(card, new_mac_address)
            status = True
        except pyric.error:
            LOGGER.exception("Failed to change MAC address!")

    return MacResult(status, old_mac_address, new_mac_address)


def set_interface_mode(interface_name, mode, card=None):
    # type: (str, str, Any) -> bool
    """Set the specified mode for the interface

    .. note: Available modes are unspecified, ibss, managed, AP
        AP VLAN, wds, monitor, mesh, p2p.

    Example:
        >>> set_interface_mode("valid", "managed")
        True

        >>> set_interface_mode("invalid", "NOMODE")
        False
    """
    interface_card = card
    succeeded = False

    if not card:
        interface_card = get_interface_card(interface_name)

    if interface_card and pyw.validcard(interface_card) and turn_interface(
            interface_name, turn_on=False, card=interface_card):
        try:
            pyw.modeset(interface_card, mode)
        except pyric.error:
            LOGGER.exception("Failed to set %s to %s", interface_name, mode)
        else:
            succeeded = turn_interface(
                interface_name, turn_on=True, card=interface_card)

    return succeeded


def turn_interface(interface_name, turn_on=True, card=None):
    # type: (str, bool, Any) -> bool
    """Turn the interface on or off.

    Turn the interface on if turn_on is True and off otherwise. Provide
    card to speed up the process as it no longer needs to look it up.
    """
    interface_card = card
    succeeded = False

    if not card:
        interface_card = get_interface_card(interface_name)

    if interface_card and pyw.validcard(interface_card):
        try:
            if turn_on:
                pyw.up(interface_card)
            else:
                pyw.down(interface_card)
        except pyric.error:
            state = "ON" if turn_on else "OFF"
            LOGGER.exception("Failed to turn %s %s!", interface_name, state)
        else:
            succeeded = True

    return succeeded


def set_interface_channel(interface_name, channel, card=None):
    # type: (str, int, Any) -> bool
    """Set the channel for the interface.

    Set the provided channel for interface_name. Card can be provided
    to increase speeds as it no longer does a card lookup.

    Example:

        >>> set_interface_channel("valid", 2)
        True

        >>> set_interface_channel("invalid", 23)
        False
    """

    interface_card = card
    succeeded = False

    if not card:
        interface_card = get_interface_card(interface_name)

    if interface_card and pyw.validcard(interface_card):
        try:
            pyw.chset(interface_card, channel)
        except pyric.error:
            LOGGER.exception("Failed to set %s to channel %s", interface_name,
                             channel)
        else:
            succeeded = True

    return succeeded


def find_interface(mode, exclude=[]):
    # type: (str, List[str]) -> FindResult
    """Return an interface with the given mode.

    The function prioritizes physical interfaces over virtual ones.

    .. note: exclude does not exclude the interface from search. It
        only gives priority to other physical interfaces

    :Example:
        # assuming 2 interface
        # name      modes
        # wlan1 - AP, monitor
        # wlan2 - monitor
        >>> find_interface("monitor", exclude=["wlan1"])
        FindResult(name='wlan2', is_virtual=False)
    """
    interface = ""
    alternative_interface = ""

    for wireless_interface in pyw.winterfaces():
        if has_mode(wireless_interface, mode):
            if wireless_interface not in exclude:
                interface = wireless_interface
                break
            elif not alternative_interface:
                alternative_interface = wireless_interface

    if interface:
        result = FindResult(interface, False)
    elif alternative_interface:
        result = FindResult(alternative_interface, True)
    else:
        result = FindResult("", False)

    return result


def validate_or_find_interface(interface_name, mode, exclude=[]):
    # type: (str, str, List[str]) -> FindResult
    """Validate or find an interface with given mode.

    If the provided interface is valid and has the given name return that
    otherwise try to find an interface with that mode.

    Example:
        >>> validate_or_find_interface("valid", "monitor")
        FindResult(name='valid', is_virtual=False)
    """
    name = ""
    is_virtual = False

    if interface_name and pyw.isinterface(interface_name) and has_mode(
            interface_name, mode):
        name = interface_name
        is_virtual = False
    elif not interface_name:
        result = find_interface(mode, exclude)
        if result.name:
            name = result.name
            is_virtual = result.is_virtual

    return FindResult(name, is_virtual)


def try_freeing_interface(interface_name):
    # type: (str) -> bool
    """Try to free interface_name from network manager

    Return True if interface_name is not controlled by network
    manager and False otherwise. This function will try to
    free the interface regardless of if it is managed or not.

    Example:
        >>> try_freeing_interface("managed")
        True
    """
    succeeded = False

    try:
        subprocess.check_call(
            ["nmcli", "dev", "set", interface_name, "managed", "no"],
            stdout=constants.DN,
            stderr=constants.DN)
    except subprocess.CalledProcessError:
        LOGGER.exception("Failed to remove %s from network manager",
                         interface_name)
    else:
        succeeded = True

    return succeeded


def create_virtual_interface(interface_name):
    # type: (str) -> str
    """Create a new virtual interface for interface_name

    .. note: New virtual interface will be in managed mode and turned off
    """
    succeeded = False
    card = get_interface_card(interface_name)
    new_interface_name = "wifiphisher{}".format(random.randint(1, 10000))

    if card and turn_interface(interface_name, turn_on=False, card=card):
        try:
            pyw.devadd(card, new_interface_name, "managed")
        except pyric.error:
            LOGGER.exception("Unable to create a virtual interface for %s",
                             interface_name)
        else:
            succeeded = True

    return new_interface_name if succeeded else ""


def setup_interfaces(monitor_interface, ap_interface, internet_interface):
    # type: (str, str, str) -> TwoInterfaceResult
    """
    """
    final_extention_interface = ""
    final_server_interface = ""

    extention_interface, extention_virtual = validate_or_find_interface(
        monitor_interface, "monitor")
    server_interface, server_virtual = validate_or_find_interface(
        ap_interface, "AP", [monitor_interface])

    if extention_interface and server_interface and not try_freeing_interface(
            extention_interface) and not try_freeing_interface(server_interface):
        if extention_virtual:
            final_extention_interface = create_virtual_interface(
                extention_interface)
        else:
            final_extention_interface = extention_interface

        if server_virtual:
            final_server_interface = create_virtual_interface(server_interface)
        else:
            final_server_interface = server_interface

    return TwoInterfaceResult(
        bool(final_extention_interface
             and final_server_interface), final_extention_interface,
        final_server_interface, extention_virtual, server_virtual)


def has_mode(interface_name, mode):
    # type: (str, str) -> bool
    """Return whether the provided interface has the provided mode.

    :Example:
        >>> has_mode("DoesNotExist", "AP")
        False

        >>> has_mode("HasAP", "AP")
        True
    """
    modes = []  # type: List[str]

    card = get_interface_card(interface_name)

    if card:
        try:
            modes = pyw.devmodes(card)
        except pyric.error:
            LOGGER.exception("Failed to retrieve %s modes", interface_name)

    return mode in modes


def get_interface_card(interface_name):
    # type: (str) -> Optional[pyw.Card]
    """Return the card object for the given interface.

    Try to get the card for the provided interface. It will handle
    the case if the interface is invalid or non-existent.

    .. note: If the status is False the card is guaranteed to be None

    :Example:

        >>> result = get_interface_card("valid_card")
        >>> result
        (status=True, card=Card(phy=0,dev=valid_card, ifindex=3))

        >>> result = get_interface_card("bad_card")
        >>> result
        (status=False, card=None)
    """
    card = None

    try:
        card = pyw.getcard(interface_name)
    except pyric.error:
        LOGGER.exception("Failed to get the card object for %s",
                         interface_name)
    return card
