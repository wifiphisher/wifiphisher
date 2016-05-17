#!/usr/bin/env python

""" sockios_h.py: definitions of the socket-level I/O control calls.

A port of sockios.h (and two constants from wireless.h) to python
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions of the socket-level I/O control calls.
 *
 * Version:	@(#)sockios.h	1.0.2	03/09/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

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

Most of these constants are not used but are left for possible future use.

"""

__name__ = 'sockios_h'
__license__ = 'GPLv3'
__version__ = '0.0.2'
__date__ = 'February 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

# Linux-specific socket ioctls
#SIOCINQ  = FIONREAD
#SIOCOUTQ = TIOCOUTQ # output queue size (not sent + not acked)

# Routing table calls
SIOCADDRT = 0x890B # add routing table entry
SIOCDELRT = 0x890C # delete routing table entry
SIOCRTMSG = 0x890D # call to routing system

# Socket configuration controls from wireless.h
SIOCGIWNAME  = 0x8B01 # get name (standards can be retrieved here)
SIOCGIWTXPOW = 0x8B27 # get transmit power
SIOCGIWFREQ	 = 0x8B05 # get frequency

# Socket configuration controls
SIOCGIFNAME        = 0x8910 # get iface name
SIOCSIFLINK        = 0x8911 # set iface channel
SIOCGIFCONF        = 0x8912 # get iface list
SIOCGIFFLAGS       = 0x8913 # get flags
SIOCSIFFLAGS       = 0x8914 # set flags
SIOCGIFADDR        = 0x8915 # get PA address
SIOCSIFADDR        = 0x8916 # set PA address
SIOCGIFDSTADDR     = 0x8917 # get remote PA address
SIOCSIFDSTADDR     = 0x8918 # set remote PA address
SIOCGIFBRDADDR     = 0x8919 # get broadcast PA address
SIOCSIFBRDADDR     = 0x891a # set broadcast PA address
SIOCGIFNETMASK     = 0x891b # get network PA mask
SIOCSIFNETMASK     = 0x891c # set network PA mask
SIOCGIFMETRIC      = 0x891d # get metric
SIOCSIFMETRIC      = 0x891e # set metric
SIOCGIFMEM         = 0x891f # get memory address (BSD)
SIOCSIFMEM         = 0x8920 # set memory address (BSD)
SIOCGIFMTU         = 0x8921 # get MTU size
SIOCSIFMTU         = 0x8922 # set MTU size
SIOCSIFNAME        = 0x8923 # set interface name
SIOCSIFHWADDR      = 0x8924 # set hardware address
SIOCGIFENCAP       = 0x8925 # get/set encapsulations
SIOCSIFENCAP       = 0x8926
SIOCGIFHWADDR      = 0x8927 # Get hardware address
SIOCGIFSLAVE       = 0x8929 # Driver slaving support
SIOCSIFSLAVE       = 0x8930
SIOCADDMULTI       = 0x8931 # Multicast address lists
SIOCDELMULTI       = 0x8932
SIOCGIFINDEX       = 0x8933 # name -> if_index mapping
SIOGIFINDEX  = SIOCGIFINDEX # misprint compatibility :-)
SIOCSIFPFLAGS      = 0x8934 # set/get extended flags set
SIOCGIFPFLAGS      = 0x8935
SIOCDIFADDR        = 0x8936 # delete PA address
SIOCSIFHWBROADCAST = 0x8937 # set hardware broadcast addr
SIOCGIFCOUNT       = 0x8938 # get number of devices
SIOCGIFBR          = 0x8940 # Bridging support
SIOCSIFBR          = 0x8941 # Set bridging options
SIOCGIFTXQLEN      = 0x8942 # Get the tx queue length
SIOCSIFTXQLEN      = 0x8943 # Set the tx queue length
SIOCETHTOOL        = 0x8946 # Ethtool interface
SIOCGMIIPHY        = 0x8947 # Get address of MII PHY in use
SIOCGMIIREG        = 0x8948 # Read MII PHY register.
SIOCSMIIREG        = 0x8949 # Write MII PHY register.
SIOCWANDEV         = 0x894A # get/set netdev parameters
SIOCOUTQNSD        = 0x894B # output queue size (not sent only)

# ARP cache control calls
SIOCDARP = 0x8953 # delete ARP table entry
SIOCGARP = 0x8954 # get ARP table entry
SIOCSARP = 0x8955 # set ARP table entry

# RARP cache control calls
SIOCDRARP = 0x8960 # delete RARP table entry
SIOCGRARP = 0x8961 # get RARP table entry
SIOCSRARP = 0x8962 # set RARP table entry

# Driver configuration calls
SIOCGIFMAP = 0x8970 # Get device parameters
SIOCSIFMAP = 0x8971 # Set device parameters

# DLCI configuration calls
SIOCADDDLCI	= 0x8980 # Create new DLCI device
SIOCDELDLCI	= 0x8981 # Delete DLCI device

SIOCGIFVLAN	= 0x8982 # 802.1Q VLAN support
SIOCSIFVLAN	= 0x8983 # Set 802.1Q VLAN options

# bonding calls
SIOCBONDENSLAVE	       = 0x8990	# enslave a device to the bond
SIOCBONDRELEASE        = 0x8991	# release a slave from the bond
SIOCBONDSETHWADDR      = 0x8992	# set the hw addr of the bond
SIOCBONDSLAVEINFOQUERY = 0x8993 # rtn info about slave state
SIOCBONDINFOQUERY      = 0x8994	# rtn info about bond state
SIOCBONDCHANGEACTIVE   = 0x8995 # update to a new active slave

# bridge calls
SIOCBRADDBR = 0x89a0 # create new bridge device
SIOCBRDELBR = 0x89a1 # remove bridge device
SIOCBRADDIF = 0x89a2 # add interface to bridge
SIOCBRDELIF = 0x89a3 # remove interface from bridge

# hardware time stamping: parameters in linux/net_tstamp.h
SIOCSHWTSTAMP = 0x89b0 # set and get config
SIOCGHWTSTAMP = 0x89b1 # get config