#!/usr/bin/env python

""" netlink_h.py: port of netlink.h public header
/*
 * netlink/netlink.h		Netlink Interface
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
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

A port of netlink.h, netlink/attr.h netlink/errno.h to python

"""

# NOTE: get the below error when calling import netlink_h
#RuntimeWarning: Parent module 'netlink_h' not found while handling absolute import
#  import struct
# unless I comment out the name
#__name__ = 'netlink_h.py'
__license__ = 'GPLv3'
__version__ = '0.0.3'
__date__ = 'March 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct

NETLINK_ROUTE          =  0	# Routing/device hook
NETLINK_UNUSED         =  1	# Unused number
NETLINK_USERSOCK       =  2	# Reserved for user mode socket protocols
NETLINK_FIREWALL       =  3	# Unused number, formerly ip_queue
NETLINK_SOCK_DIAG      =  4	# socket monitoring
NETLINK_NFLOG          =  5	# netfilter/iptables ULOG
NETLINK_XFRM           =  6	# ipsec
NETLINK_SELINUX        =  7	# SELinux event notifications
NETLINK_ISCSI		   =  8	# Open-iSCSI
NETLINK_AUDIT          =  9	# auditing
NETLINK_FIB_LOOKUP     = 10
NETLINK_CONNECTOR      = 11
NETLINK_NETFILTER      = 12	# netfilter subsystem
NETLINK_IP6_FW         = 13
NETLINK_DNRTMSG        = 14	# DECnet routing messages
NETLINK_KOBJECT_UEVENT = 15	# Kernel messages to userspace
NETLINK_GENERIC        = 16
#leave room for NETLINK_DM (DM Events)
NETLINK_SCSITRANSPORT  = 18	# SCSI Transports
NETLINK_ECRYPTFS       = 19
NETLINK_RDMA           = 20
NETLINK_CRYPTO         = 21	# Crypto layer
__NETLINK_TYPE_MAX     = 22
NETLINK_TYPE_MAX       = __NETLINK_TYPE_MAX - 1

NETLINK_INET_DIAG = NETLINK_SOCK_DIAG

MAX_LINKS = 32

"""
struct sockaddr_nl {
	__kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	__u32		nl_pid;		/* port ID	*/
       	__u32		nl_groups;	/* multicast groups mask */
};
"""

"""
struct nlmsghdr {
	__u32		nlmsg_len;	 /* Length of message including header */
	__u16		nlmsg_type;	 /* Message content */
	__u16		nlmsg_flags; /* Additional flags */
	__u32		nlmsg_seq;	 /* Sequence number */
	__u32		nlmsg_pid;	 /* Sending process port ID */
};
"""
nl_nlmsghdr = "IHHII"
NLMSGHDRLEN = struct.calcsize(nl_nlmsghdr)
def nlmsghdr(mlen,nltype,flags,seq,pid):
    """
     create a nlmsghdr
     :param mlen: length of message
     :param nltype: message content
     :param flags: additional flags
     :param seq: sequence number
     :param pid: process port id
     :returns: packed netlink msg header
    """
    return struct.pack(nl_nlmsghdr,NLMSGHDRLEN+mlen,nltype,flags,seq,pid)

# Flags values
NLM_F_REQUEST   =  1 # It is request message.
NLM_F_MULTI     =  2 # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK       =  4 # Reply with ack, with zero or error code
NLM_F_ECHO      =  8 # Echo this request
NLM_F_DUMP_INTR = 16 # Dump was inconsistent due to sequence change

# Modifiers to GET request
NLM_F_ROOT   = 0x100 # specify tree	root
NLM_F_MATCH  = 0x200 # return all matching
NLM_F_ATOMIC = 0x400 # atomic GET
NLM_F_DUMP   = (NLM_F_ROOT|NLM_F_MATCH)

# Modifiers to NEW request
NLM_F_REPLACE = 0x100 # Override existing
NLM_F_EXCL    = 0x200 # Do not touch, if it exists
NLM_F_CREATE  = 0x400 # Create, if it does not exist
NLM_F_APPEND  = 0x800 # Add to end of list

"""
/*
   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
   4.4BSD CHANGE	NLM_F_REPLACE

   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
   Append		NLM_F_CREATE
   Check		NLM_F_EXCL
 */
"""

# Most netlink protocols enforce a strict alignment policy for all boundries.
# The alignment value is defined by NLMSG_ALIGNTO and is fixed to 4 bytes.
# Therefore all netlink message headers, begin of payload sections, protocol
# specific headers, and attribute sections must start at an offset which is a
# multiple of NLMSG_ALIGNTO.
#     <----------- nlmsg_total_size(len) ------------>
#     <----------- nlmsg_size(len) ------------>
#    +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -
#    |  struct nlmsghdr  | Pad |     Payload    | Pad |  struct nlsmghdr  |
#    +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -
#     <---- NLMSG_HDRLEN -----> <- NLMSG_ALIGN(len) -> <---- NLMSG_HDRLEN ---
NLMSG_ALIGNTO = 4
def NLMSG_ALIGN(l): return (l+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1)
def NLMSG_LENGTH(l): return l+NLMSGHDRLEN
def NLMSG_SPACE(l): return NLMSG_ALIGN(NLMSG_LENGTH(l))
def NLMSG_ALIGNBY(l): return NLMSG_ALIGN(l) - l
# still working the below out
#NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSGHDRLEN))
#NLMSG_NEXT(hl,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
#				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
#			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
#			   (nlh)->nlmsg_len <= (len))
#NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

NLMSG_NOOP     = 0x1 # Nothing.
NLMSG_ERROR    = 0x2 # Error
NLMSG_DONE     = 0x3 # End of a dump
NLMSG_OVERRUN  = 0x4 # Data lost

NLMSG_MIN_TYPE = 0x10 # < 0x10: reserved control messages

"""
struct nlmsgerr {
	int		error;
	struct nlmsghdr msg;
};
"""
nl_nlmsgerr = "hIHHII"
NLMSGERRLEN = struct.calcsize(nl_nlmsgerr)
NLMSGACKLEN = NLMSGHDRLEN + NLMSGERRLEN   # this is size of an error or ack message
def nlmsgerr(error,mlen,nltype,flags,seq,pid):
    """
     create a nlmsgerr
     NOTE: the function itself is here for illustrative purposes - users will
     only need the format string above to unpack these
     :param error: error code
     :param mlen: length of header
     :param nltype: message content
     :param flags: additional flags
     :param seq: sequence number
     :param pid: process port id
     :returns: packed netlink msg error
    """
    return struct.pack(nl_nlmsgerr,error,mlen,nltype,flags,seq,pid)

NETLINK_ADD_MEMBERSHIP  = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO         = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS      = 5
NETLINK_RX_RING         = 6
NETLINK_TX_RING         = 7

"""
struct nl_pktinfo {
	__u32	group;
};
"""

"""
struct nl_mmap_req {
	unsigned int	nm_block_size;
	unsigned int	nm_block_nr;
	unsigned int	nm_frame_size;
	unsigned int	nm_frame_nr;
};
"""

"""
struct nl_mmap_hdr {
	unsigned int	nm_status;
	unsigned int	nm_len;
	__u32		nm_group;
	/* credentials */
	__u32		nm_pid;
	__u32		nm_uid;
	__u32		nm_gid;
};
"""

# nume nl_nmap_status
NL_MMAP_STATUS_UNUSED   = 0
NL_MMAP_STATUS_RESERVED = 1
NL_MMAP_STATUS_VALID    = 2
NL_MMAP_STATUS_COPY     = 3
NL_MMAP_STATUS_SKIP     = 4

#NL_MMAP_MSG_ALIGNMENT		NLMSG_ALIGNTO
#NL_MMAP_MSG_ALIGN(sz)		__ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)
#NL_MMAP_HDRLEN			NL_MMAP_MSG_ALIGN(sizeof(struct nl_mmap_hdr))

NET_MAJOR = 36 # Major 36 is reserved for networking

NETLINK_UNCONNECTED = 0
NETLINK_CONNECTED   = 1

"""
/*
* netlink/attr.h               Netlink Attributes
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation version 2.1
 *      of the License.
 *
 * Copyright (c) 2003-2013 Thomas Graf <tgraf@suug.ch>
 *
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */
"""

# Attribute Datatypes
NLA_DATATYPES = ['unspec','u8','u16','u32','u64','string','flag','msecs','nested']
NLA_ERROR      = -1 # my own -> failed to unpack attribute, treat as unspec
NLA_UNSPEC     =  0	# Unspecified type, binary data chunk
NLA_U8         =  1  # 8 bit integer
NLA_U16        =  2	# 16 bit integer
NLA_U32        =  3	# 32 bit integer
NLA_U64        =  4	# 64 bit integer
NLA_STRING     =  5	# NUL terminated character string
NLA_FLAG       =  6	# Flag
NLA_MSECS      =  7	# Micro seconds (64bit)
NLA_NESTED     =  8	# Nested attributes
__NLA_TYPE_MAX =  9
NLA_TYPE_MAX   = __NLA_TYPE_MAX - 1

"""
struct nlattr {
	__u16           nla_len; # length of attribute + nlattr size
	__u16           nla_type;
};
"""
nl_nlattrhdr = "HH"
NLATTRHDRLEN = struct.calcsize(nl_nlattrhdr)
def nlattrhdr(alen,atype):
    """
     create a nlattr
     :param alen: length of attribute
     :param atype: type of attribute
     return packed netlink attribute
    """
    return struct.pack(nl_nlattrhdr,alen+NLATTRHDRLEN,atype)

"""
/*
 * nla_type (16 bits)
 * +---+---+-------------------------------+
 * | N | O | Attribute Type                |
 * +---+---+-------------------------------+
 * N := Carries nested attributes
 * O := Payload stored in network byte order
 *
 * Note: The N and O flag are mutually exclusive.
 */
"""
NLA_F_NESTED		= (1 << 15)
NLA_F_NET_BYTEORDER	= (1 << 14)
NLA_TYPE_MASK		= ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#NLA_ALIGNTO    = 4
#NLA_ALIGN(len)	= (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#NLA_HDRLEN		= ((int) NLA_ALIGN(sizeof(struct nlattr)))

# defined error codes
"""
 For ease of use, I define netlink errors (netlink/errno.h) here

/*
 * netlink/errno.h		Error Numbers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */
"""
# only use success and failure -> using errno for other error numbers
NLE = ['Success','Unspecified failure']
NLE_SUCCESS           =  0
NLE_FAILURE           =  1