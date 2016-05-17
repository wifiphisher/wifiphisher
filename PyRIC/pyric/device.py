#!/usr/bin/env python
""" device.py: utility functions

Copyright (C) 2016  Dale V. Patterson (wraith.wireless@yandex.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

Redistribution and use in source and binary forms, with or without modifications,
are permitted provided that the following conditions are met:
 o Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 o Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 o Neither the name of the orginal author Dale V. Patterson nor the names of any
   contributors may be used to endorse or promote products derived from this
   software without specific prior written permission.

Defines device functions to get driver and chipset. Should we move hwaddr from
hex string to here?

"""

__name__ = 'device'
__license__ = 'GPLv3'
__version__ = '0.0.3'
__date__ = 'August 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

from os import listdir

dpath = '/proc/net/dev' # system device details
drvpath = '/sys/class/net/{0}/device/driver/module/drivers' # format w/ device name
phypath = '/sys/class/ieee80211/{0}'                        # format w/ phyiscal name
# NOTE phypath + index contains the ifindex (sometimes)

def ifdriver(dev):
    """
     :param dev: device name
     :returns: driver (or unknown)
    """
    try:
        # find the driver for nic in driver's module, split on ':' and return
        ds = listdir(drvpath.format(dev))
        if len(ds) > 1: return "Unknown"
        return ds[0].split(':')[1]
    except OSError:
        return "Unknown"

def ifchipset(driver):
    """
    returns the chipset for given driver (Thanks aircrack-ng team)
    :param driver: nic driver
    :returns: chipset of driver
    NOTE: does not fully implement the airmon-ng getChipset where identification
    requires system commands
    """
    if driver == "Unknown": return "Unknown"
    if driver == "Otus" or driver == "arusb_lnx": return "AR9001U"
    if driver == "WiLink": return "TIWLAN"
    if driver == "ath9k_htc" or driver == "usb": return "AR9001/9002/9271"
    if driver.startswith("ath") or driver == "ar9170usb": return "Atheros"
    if driver == "zd1211rw_mac80211": return "ZyDAS 1211"
    if driver == "zd1211rw": return "ZyDAS"
    if driver.startswith("acx"): return "TI ACX1xx"
    if driver == "adm8211": return "ADMtek 8211"
    if driver == "at76_usb": return "Atmel"
    if driver.startswith("b43") or driver == "bcm43xx": return "Broadcom"
    if driver.startswith("p54") or driver == "prism54": return "PrismGT"
    if driver == "hostap": return "Prism 2/2.5/3"
    if driver == "r8180" or driver == "rtl8180": return "RTL8180/RTL8185"
    if driver == "rtl8187" or driver == "r8187": return "RTL8187"
    if driver == "rt2570" or driver == "rt2500usb": return "Ralink 2570 USB"
    if driver == "rt2400" or driver == "rt2400pci": return "Ralink 2400 PCI"
    if driver == "rt2500" or driver == "rt2500pci": return "Ralink 2560 PCI"
    if driver == "rt61" or driver == "rt61pci": return "Ralink 2561 PCI"
    if driver == "rt73" or driver == "rt73usb": return "Ralink 2573 USB"
    if driver == "rt2800" or driver == "rt2800usb" or driver == "rt3070sta": return "Ralink RT2870/3070"
    if driver == "ipw2100": return "Intel 2100B"
    if driver == "ipw2200": return "Intel 2200BG/2915ABG"
    if driver == "ipw3945" or driver == "ipwraw" or driver == "iwl3945": return "Intel 3945ABG"
    if driver == "ipw4965" or driver == "iwl4965": return "Intel 4965AGN"
    if driver == "iwlagn" or driver == "iwlwifi": return "Intel 4965/5xxx/6xxx/1xxx"
    if driver == "orinoco": return "Hermes/Prism"
    if driver == "wl12xx": return "TI WL1251/WL1271"
    if driver == "r871x_usb_drv": return "Realtek 81XX"
    return "Unknown"