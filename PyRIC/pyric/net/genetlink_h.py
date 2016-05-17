#!/usr/bin/env python

""" genetlink_h.py: port of netlink.h public header
/*
 * NETLINK      Generic Netlink Family
 *
 *              Authors:        Jamal Hadi Salim
 *                              Thomas Graf <tgraf@suug.ch>
 *                              Johannes Berg <johannes@sipsolutions.net>
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

A port of genetlink.h to python. Includes as well the nla_policy for generic
netlink attributes.

"""

#__name__ = 'genetlink_h.py'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'March 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import struct

GENL_NAMSIZ	= 16 # length of family name

GENL_MIN_ID	= 0x10 # hardcoded from netlink_h
GENL_MAX_ID	= 1023

"""
struct genlmsghdr {
	__u8	cmd;
	__u8	version;
	__u16	reserved;
};
"""
genl_genlmsghdr = "BBH"
GENLMSGHDRLEN = struct.calcsize(genl_genlmsghdr)
def genlmsghdr(cmd,vers=1):
    """
     create a generic netlink header
     :param cmd: message type of genetlink service
     :param vers: revision value for backward compatability
     :returns: packed generic netlink header
    """
    return struct.pack(genl_genlmsghdr,cmd,vers,0)

#GENL_HDRLEN	NLMSG_ALIGN(sizeof(struct genlmsghdr))

GENL_ADMIN_PERM		= 0x01
GENL_CMD_CAP_DO		= 0x02
GENL_CMD_CAP_DUMP	= 0x04
GENL_CMD_CAP_HASPOL	= 0x08

# List of reserved static generic netlink identifiers:
GENL_ID_GENERATE  = 0
GENL_ID_CTRL	  = 0x10 # hardcoded from netlink_h
GENL_ID_VFS_DQUOT = GENL_ID_CTRL + 1
GENL_ID_PMCRAID	  = GENL_ID_CTRL + 2


#Controller
CTRL_CMD_UNSPEC       =  0
CTRL_CMD_NEWFAMILY    =  1
CTRL_CMD_DELFAMILY    =  2
CTRL_CMD_GETFAMILY    =  3
CTRL_CMD_NEWOPS       =  4
CTRL_CMD_DELOPS       =  5
CTRL_CMD_GETOPS       =  6
CTRL_CMD_NEWMCAST_GR  =  7
CTRL_CMD_DELMCAST_GRP =  8
CTRL_CMD_GETMCAST_GRP =  9 # unused
__CTRL_CMD_MAX        = 10
CTRL_CMD_MAX          = __CTRL_CMD_MAX - 1

CTRL_ATTR_UNSPEC       = 0
CTRL_ATTR_FAMILY_ID    = 1
CTRL_ATTR_FAMILY_NAME  = 2
CTRL_ATTR_VERSION      = 3
CTRL_ATTR_HDRSIZE      = 4
CTRL_ATTR_MAXATTR      = 5
CTRL_ATTR_OPS          = 6
CTRL_ATTR_MCAST_GROUPS = 7
__CTRL_ATTR_MAX        = 9
CTRL_ATTR_MAX          = __CTRL_ATTR_MAX - 1

CTRL_ATTR_OP_UNSPEC = 0
CTRL_ATTR_OP_ID     = 1
CTRL_ATTR_OP_FLAGS  = 2
__CTRL_ATTR_OP_MAX  = 3
CTRL_ATTR_OP_MAX    = __CTRL_ATTR_OP_MAX - 1
nla_policy_attr_op = []

CTRL_ATTR_MCAST_GRP_UNSPEC = 0
CTRL_ATTR_MCAST_GRP_NAME   = 1
CTRL_ATTR_MCAST_GRP_ID     = 2
__CTRL_ATTR_MCAST_GRP_MAX  = 3
CTRL_ATTR_MCAST_GRP_MAX    = __CTRL_ATTR_MCAST_GRP_MAX - 1
nla_policy_attr_mcast = []