#!/usr/bin/env python

""" pyw.py: python iw

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

Provides a python version of a subset of the iw command & additionally, a smaller
subset of ifconfig/iwconfig.

Each command/function (excluding interfaces & isinterface which do not rely on
ioctl/netlink sockets) comes in two flavors - one-time & persistent.
 1) one-time: similar to iw. The command, creates the netlink socket (or ioctl),
    composes the message, sends the message & receives the response, parses
    the results, closes the socket & returns the results to the caller. At
    no time does the caller need to be aware of any underlying netlink processes
    or structures.
 2) persistent: communication & parsing only. The onus of socket creation and
    deletion is on the caller which allows them to create one (or more) socket(s).
    The pyw functions will only handle message construction, message sending and
    receiving & message parsing.

Callers that intend to use pyw functionality often & repeatedly may prefer to
use a persistent netlink/ioctl socket. Socket creation & deletion are relatively
fast however, if a program is repeatedly using pyw function(s) (such as a scanner
that is changing channels mulitple times per second) it makes sense for the caller
to create a socket one time only & use the same socket. However, if the caller
is only using pyw periodically and/or does not want to bothered with socket
maintenance, the one-time flavor would be better.

Previously (v 0.0.*), two functions were used, one named <cmd> & one named
<cmd>ex (which took an additional argument, namely the socket). This yielded
additional code, was unwieldy to use & did not look "pretty".

pyw v 0.1.* uses (for lack of a better naming convention) templates & a stub
to accomplish this.

A stripped-down function template (for netlink) is defined as:

def fcttemplate(arg0,arg1,...,argn,*argv):
    # parameter validation if necessary
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(fcttemplate,arg0,arg1,...argn)

    # command execution
    ...
    return results

If argv has a netlink socket at index 0, the template will jump to execution. If
there is no socket, execute the stub to create one. (Also, if something other than
a socket is at argv[0], an error will rise during execution.) at The stub function
is then defined as:

def _nlstub_(fct,*argv):
    nlsock = None
    try:
        nlsock = nlsock = nl.nl_socket_alloc()
        argv = list(argv) + [nlsock]
        return fct(*argv)
    except pyric.error: raise # catch & release
    finally:
        if nlsock: nl.nl_socket_free(nlsock)

which creates a NLSocket & "recalls" the template with the socket now in *argv. so,
callers can now call for example,

regset('US')

for one-time execution, or

regset('US',<nlsocket>)

for persistent execution.

Additional changes in pyw v 0.1.*
 1) All functions (excluding wireless core related) will use a Card object which
    encapsulates the physical index, device name and interface index (ifindex)
    under a tuple rather than a device name or physical index or ifindex as this
    will not require the caller to remember if a dev or a phy or a ifindex is
    needed. The only exception to this is devinfo which by necessity will accept
    a Card or a device name
 2) All functions allow pyric errors to pass through.
 3) sets the tx/rx buffer depending on the function
"""

__name__ = 'pyw'
__license__ = 'GPLv3'
__version__ = '0.1.3'
__date__ = 'May 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct                                   # ioctl unpacking
import PyRIC.pyric,errno                              # pyric exception & error codes
from PyRIC.pyric import device                        # device related
from PyRIC.pyric import channels                      # channel related
from PyRIC.pyric.docs.nlhelp import cmdbynum          # get command name
import PyRIC.pyric.net.netlink_h as nlh               # netlink definition
import PyRIC.pyric.net.genetlink_h as genlh           # genetlink definition
import PyRIC.pyric.net.wireless.nl80211_h as nl80211h # 802.11 definition
import PyRIC.pyric.net.sockios_h as sioch             # sockios constants
import PyRIC.pyric.net.if_h as ifh                    # ifreq structure
import PyRIC.pyric.lib.libnl as nl                    # netlink functions
import PyRIC.pyric.lib.libio as io                    # sockios functions

_FAM80211ID_ = None

# redefine interface types and monitor flags
IFTYPES = nl80211h.NL80211_IFTYPES
MNTRFLAGS = nl80211h.NL80211_MNTR_FLAGS

class Card(tuple):
    """
     Wrapper around a tuple t = (physical index,device name, interface index)
     Exposes the following properties: (callable by '.'):
      phy: physical index
      dev: device name
      idx: interface index (ifindex)
    """
    def __new__(cls,p,d,i): return super(Card,cls).__new__(cls,tuple((p,d,i)))
    def __repr__(self):
        return "Card(phy={0},dev={1},ifindex={2})".format(self.phy,self.dev,self.idx)
    @property
    def phy(self): return self[0]
    @property
    def dev(self): return self[1]
    @property
    def idx(self): return self[2]

################################################################################
#### WIRELESS CORE                                                          ####
################################################################################

def interfaces():
    """
     retrieves all network interfaces (APX ifconfig)
     :returns: a list of device names of current network interfaces cards
    """
    fin = None
    try:
        # read in devices from /proc/net/dev. After splitting on newlines, the
        # first 2 lines are headers and the last line is empty so we remove them
        fin = open(device.dpath,'r')
        ds = fin.read().split('\n')[2:-1]
    except IOError:
        return []
    finally:
        if fin: fin.close()

    # the remaining lines are <dev>: p1 p2 ... p3, split on ':' & strip whitespace
    return [d.split(':')[0].strip() for d in ds]

def isinterface(dev):
    """
     determines if device name belongs to a network card (APX ifconfig <dev>)
     :param dev: device name
     :returns: {True if dev is a device|False otherwise}
    """
    return dev in interfaces()

def winterfaces(*argv):
    """
     retrieve all wireless interfaces (APX iwconfig)
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: list of device names of current wireless NICs
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(winterfaces)

    wifaces = []
    for dev in interfaces():
        try:
            #_ = io.io_transfer(iosock,sioch.SIOCGIWNAME,ifh.ifreq(dev))
            #wifaces.append(dev)
            if iswireless(dev,iosock): wifaces.append(dev)
        except PyRIC.pyric.error as e:
            # ENODEV & EOPNOTSUPP mean not wireless, reraise any others
            if e.errno == errno.ENODEV or e.errno == errno.EOPNOTSUPP: pass
            else: raise
    return wifaces

def iswireless(dev,*argv):
    """
     determines if given device is wireless (APX iwconfig <dev>)
     :param dev: device name
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: {True:device is wireless|False:device is not wireless/not present}
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(iswireless,dev)

    try:
        # if the call succeeds, found to be wireless
        _ = io.io_transfer(iosock,sioch.SIOCGIWNAME,ifh.ifreq(dev))
        return True
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except PyRIC.pyric.error as e:
        # ENODEV or ENOTSUPP means not wireless, reraise any others
        if e.errno == errno.ENODEV or e.errno == errno.EOPNOTSUPP: return False
        else: raise

def regget(*argv):
    """
     gets the current regulatory domain (iw reg get)
     :param argv: netlink socket at argv[0] (or empty)
     :returns: the two charactor regulatory domain
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(regget)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_GET_REG,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nl_sendmsg(nlsock,msg)
    rmsg = nl.nl_recvmsg(nlsock)
    return nl.nla_find(rmsg,nl80211h.NL80211_ATTR_REG_ALPHA2)

def regset(rd,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     sets the current regulatory domain (iw reg set <rd>)
     :param rd: regulatory domain code
     :param argv: netlink socket at argv[0] (or empty)
     :returns: the two charactor regulatory domain
    """
    if len(rd) != 2: raise PyRIC.pyric.error(errno.EINVAL,"Invalid reg. domain")
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(regset,rd)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_REQ_SET_REG,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_string(msg,rd.upper(),nl80211h.NL80211_ATTR_REG_ALPHA2)
    nl.nl_sendmsg(nlsock,msg)
    nl.nl_recvmsg(nlsock) # throws exception on failure
    return True           # we got here-it worked (or there were no complaints)


################################################################################
#### WIRELESS INTERFACE FUNCTIONS                                           ####
################################################################################

def getcard(dev,*argv):
    """
     get the Card object from device name
     :param dev: device name
     :returns: a Card with device name dev
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(getcard,dev)

    return devinfo(dev,nlsock)['card']

def validcard(card,*argv):
    """
     determines if card is still valid i.e. another program has not changed it
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True if card is still valid, False otherwise
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(validcard,card)
    try:
        return card == devinfo(card.dev,nlsock)['card']
    except PyRIC.pyric.error as e:
        if e.errno == errno.ENODEV: return False
        else: raise

def macget(card,*argv):
    """
     gets the interface's hw address (APX ifconfig <card.dev> | grep HWaddr)
     :param card: Card object
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: device mac
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(macget,card)

    try:
        flag = sioch.SIOCGIFHWADDR
        ret = io.io_transfer(iosock,flag,ifh.ifreq(card.dev,flag))
        return _hex2mac_(ret[18:24])
        # sometimes get value 803 as family, cannot find any reference to this
        # until then, just hope we get a mac as we should
        #fam = struct.unpack_from(ifh.sa_addr, ret, ifh.IFNAMELEN)[0]
        #if fam == ifh.ARPHRD_ETHER or fam == ifh.AF_UNSPEC:  # confirm we got a hwaddr back
        #    return _hex2mac_(ret[18:24])
        #else:
        #    raise pyric.error(errno.EAFNOSUPPORT, "Invalid return addr family {0}".format(fam))
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"Error parsing results {0}".format(e))

def macset(card,mac,*argv):
    """
     REQUIRES ROOT PRIVILEGES/CARD DOWN
     get/set nic's hwaddr (ifconfig <card.dev> hw ether <mac>)
     :param card: Card object
     :param mac: macaddr to set
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: mac address after operation
     TODO: add parameter check on mac address
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(macset,card,mac)

    try:
        flag = sioch.SIOCSIFHWADDR
        params = [ifh.ARPHRD_ETHER,mac]
        ret = io.io_transfer(iosock,flag,ifh.ifreq(card.dev,flag,params))
        return _hex2mac_(ret[18:24])
        # see macget
        #fam = struct.unpack_from(ifh.sa_addr,ret,ifh.IFNAMELEN)[0]
        #if fam == ifh.ARPHRD_ETHER or fam == ifh.AF_UNSPEC: # confirm we got a hwaddr back
        #    return _hex2mac_(ret[18:24])
        #else:
        #    raise pyric.error(errno.EAFNOSUPPORT, "Invalid return addr family")
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"error parsing results {0}".format(e))

def up(card,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     turns dev on (ifconfig <card.dev> up)
     :param card: Card object
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: True on succes, throws exception otherwise
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(up,card)

    dev = card.dev
    flags = _flagsget_(dev,iosock)
    if not _issetf_(flags,ifh.IFF_UP):
        _flagsset_(dev,_setf_(flags,ifh.IFF_UP),iosock)
    return True

def down(card,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     turns def off (ifconfig <card.dev> down)
     :param card: Card object
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: True on succes, throws exception otherwise
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(down,card)

    dev = card.dev
    flags = _flagsget_(dev,iosock)
    if _issetf_(flags,ifh.IFF_UP):
        _flagsset_(dev,_unsetf_(flags,ifh.IFF_UP),iosock)
    return True

def txget(card,*argv):
    """
     gets the device's transimission power (iwconfig <card.dev> | grep Tx-Power)
     :param card: Card object
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: transmission power
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(txget,card)

    try:
        flag = sioch.SIOCGIWTXPOW
        ret = io.io_transfer(iosock,flag,ifh.ifreq(card.dev,flag))
        return struct.unpack_from(ifh.ifr_iwtxpwr,ret,ifh.IFNAMELEN)[0]
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except IndexError:
        return None
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"Error parsing results {0}".format(e))

def devstds(card,*argv):
    """
     gets card's wireless standards (iwconfig <card.dev> | grep IEEE
     :param card: Card object
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: returns a list standards (letter designators)
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(devstds,card)

    try:
        flag = sioch.SIOCGIWNAME
        ret = io.io_transfer(iosock,flag,ifh.ifreq(card.dev,flag))
        stds = ret[ifh.IFNAMELEN:]             # get the standards
        stds = stds[:stds.find('\x00')]        # remove nulls
        stds = stds.replace('IEEE 802.11','')  # remove IEEE 802.11
        return [std for std in stds]
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid paramter {0}".format(e))
    except IndexError: return None
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"Error parsing results {0}".format(e))

def devmodes(card,*argv):
    """
     gets supported modes card can operate in
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :returns: list of card's supported modes
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(devmodes,card)

    return phyinfo(card,nlsock)['modes']

def devcmds(card,*argv):
    """
     get supported commands card can execute
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :returns: supported commands
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(devcmds,card)

    return phyinfo(card,nlsock)['commands']

def devinfo(card,*argv):
    """
     get info for device (iw dev <dev> info)
     :param card: Card object or dev
     :param argv: netlink socket at argv[0] (or empty)
     :returns: dict with the following key:value pairs
      card -> Card(phy,dev,ifindex)
      mode -> i.e. monitor or managed
      wdev -> wireless device id
      mac -> hw address
      RF (if associated) -> frequency
      CF (if assoicate) -> center frequency
      CHW -> channel width i.e. NOHT,HT40- etc
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(devinfo,card)

    # if we have a Card, pull out dev name, ifindex itherwise get ifindex
    try:
        dev = card.dev
        idx = card.idx
    except AttributeError:
        dev = card
        idx = _ifindex_(dev)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_GET_INTERFACE,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,idx,nl80211h.NL80211_ATTR_IFINDEX)
    nl.nl_sendmsg(nlsock,msg)
    rmsg = nl.nl_recvmsg(nlsock)

    # pull out attributes
    info = {'card':Card(nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY),dev,idx),
            'mode':IFTYPES[nl.nla_find(rmsg,nl80211h.NL80211_ATTR_IFTYPE)],
            'wdev':nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WDEV),
            'mac':_hex2mac_(nl.nla_find(rmsg,nl80211h.NL80211_ATTR_MAC)),
            'RF':nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_FREQ),
            'CF':nl.nla_find(rmsg,nl80211h.NL80211_ATTR_CENTER_FREQ1),
            'CHW':None}
    chw = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_CHANNEL_WIDTH)
    if chw: info['CHW'] = channels.CHWIDTHS[chw]
    return info

def phyinfo(card,*argv):
    """
     get info for phy (iw phy <phy> info)
     :param card: Card
     :param argv: netlink socket at argv[0] (or empty)
     :returns: dict with the following key:value pairs
      modes -> list of supported modes
      bands -> list of supported bands (still working on unpacking)
      scan_ssids -> max number of scan SSIDS
      retry_short -> retry short limit
      retry_long -> retry long limit
      frag_thresh -> frag threshold
      rts_thresh -> rts threshold
      cov_class -> coverage class
      swmodes -> supported software modes
      commands -> supported commands

     NOTE: function is still in experimental stage, still working through how
      the nested attributes should be treated. ATT have found that:
       modes,swmodes are big-endian unsigned shorts corresponding to nl80211_iftype
       commands are a tuple of big-endian unsigned shorts t=(idx,cmd) where
       idx is the current index in the list of supported commands and
       cmd correpsonds to nl80211_commands
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(phyinfo,card)

    # iw sends a @NL80211_ATTR_SPLIT_WIPHY_DUMP, we don't & get full return at once
    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_GET_WIPHY,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.phy,nl80211h.NL80211_ATTR_WIPHY)
    nl.nl_sendmsg(nlsock,msg)
    rmsg = nl.nl_recvmsg(nlsock)

    # pull out attributes
    info = {'scan_ssids':None,'modes':None,'bands':None,'retry_short':None,
            'retry_long':None,'frag_thresh':None,'rts_thresh':None,
            'cov_class':None,'swmodes':None,'commands':None}
    # singular attributes
    info['bands'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_BANDS)
    info['retry_short'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_RETRY_SHORT)
    info['retry_long'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_RETRY_LONG)
    info['retry_short'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_RETRY_SHORT)
    info['frag_thresh'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_FRAG_THRESHOLD)
    info['rts_thresh'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_RTS_THRESHOLD)
    info['cov_class'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_WIPHY_COVERAGE_CLASS)
    info['scan_ssids'] = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_MAX_NUM_SCAN_SSIDS)
    # nested attributes (for whatever reason, these use big-endian)
    modes = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_SUPPORTED_IFTYPES)
    info['modes'] = [_iftypes_(struct.unpack('>H',mode)[0]) for mode in modes]
    modes = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_SOFTWARE_IFTYPES)
    info['swmodes'] = [_iftypes_(struct.unpack('>H', mode)[0]) for mode in modes]
    cmds = nl.nla_find(rmsg,nl80211h.NL80211_ATTR_SUPPORTED_COMMANDS)
    info['commands'] = []
    for cmd in cmds:
        try:
            cmd = cmdbynum(struct.unpack_from('>HH',cmd,0)[1])
            if type(cmd) is type([]): cmd = cmd[0]
            info['commands'].append(cmd[13:].lower())
        except KeyError:
            info['commands'].append("unknown cmd ({0})".format(cmd))
    return info

def ifaces(card,*argv):
    """
     returns all interfaces sharing the same phy as card (APX iw dev | grep phy#)
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :returns: a list of tuples t = (Card,mode) for each device having the same
      phyiscal index as that of card
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(ifaces,card)

    ifs = []
    for dev in winterfaces():
        info = devinfo(dev,nlsock)
        if info['card'].phy == card.phy: ifs.append((info['card'],info['mode']))
    return ifs

def chget(card,*argv):
    """
     gets the current channel for device (iw dev <card.dev> info | grep channel)
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     NOTE:
      o ATT will only work if dev is associated w/ AP
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(chget,card)
    return channels.rf2ch(devinfo(card.dev,nlsock)['RF'])

def freqset(card,rf,chw=None,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     set the frequency and width
     :param card: Card object
     :param rf: frequency
     :param chw: channel width oneof {[None|'HT20'|'HT40-'|'HT40+'}
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True on success
    """
    if rf not in channels.freqs():  raise PyRIC.pyric.error(errno.EINVAL,"Invalid frequency")
    if chw not in channels.CHWIDTHS: raise PyRIC.pyric.error(errno.EINVAL,"Invalid channel width")
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(freqset,card,rf,chw)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_SET_WIPHY,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.phy,nl80211h.NL80211_ATTR_WIPHY)
    nl.nla_put_u32(msg,rf,nl80211h.NL80211_ATTR_WIPHY_FREQ)
    nl.nla_put_u32(msg,channels.CHWIDTHS.index(chw),
                   nl80211h.NL80211_ATTR_WIPHY_CHANNEL_TYPE)
    nl.nl_sendmsg(nlsock,msg)
    nl.nl_recvmsg(nlsock)
    return True

def chset(card,ch,chw,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     sets current channel on device (iw phy <card.phy> set channel <ch> <chw>)
     :param card: Card object
     :param ch: channel number
     :param chw: channel width oneof {[None|'HT20'|'HT40-'|'HT40+'}
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True on success
     NOTE:
      o ATT can throw a device busy for several reason. Most likely due to
      the network manager etc.
      o On my system at least (Ubuntu), creating a new dev in monitor mode and
        deleting all other existing managed interfaces allows for the new virtual
        device's channels to be changed
    """
    if ch not in channels.channels(): raise PyRIC.pyric.error(errno.EINVAL,"Invalid channel")
    if chw not in channels.CHWIDTHS: raise PyRIC.pyric.error(errno.EINVAL,"Invalid width")
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(chset,card,ch,chw)

    return freqset(card,channels.ch2rf(ch),chw,nlsock)

def modeset(card,mode,flags=None,*argv):
    """
     REQUIRES ROOT PRIVILEGES/CARD DOWN
     sets card to mode (with optional flags if mode is monitor)
     (APX iw dev <card.dev> set type <mode> [flags])
     NOTE: as far
     :param card: Card object
     :param mode: 'name' of mode to operate in (must be one of in {'unspecified'|
     'ibss'|'managed'|'AP'|'AP VLAN'|'wds'|'monitor'|'mesh'|'p2p'}
     :param flags: list of monitor flags (can only be used if card is being set
      to monitor mode)
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True on success
    """
    if mode not in IFTYPES: raise PyRIC.pyric.error(errno.EINVAL, 'Invalid mode')
    if flags:
        if mode != 'monitor':
            raise PyRIC.pyric.error(errno.EINVAL,
                              'Can only set flags in monitor mode')
        for flag in flags:
            if flag not in MNTRFLAGS:
                raise PyRIC.pyric.error(errno.EINVAL, 'Invalid flag: {0}',format(flag))
    else: flags = []

    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(modeset,card,mode,flags)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_SET_INTERFACE,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.idx,nl80211h.NL80211_ATTR_IFINDEX)
    nl.nla_put_u32(msg,IFTYPES.index(mode),nl80211h.NL80211_ATTR_IFTYPE)
    for flag in flags:
        nl.nla_put_u32(msg,MNTRFLAGS.index(flag),nl80211h.NL80211_ATTR_MNTR_FLAGS)
    nl.nl_sendmsg(nlsock,msg)
    nl.nl_recvmsg(nlsock)
    return True

def modeget(card,*argv):
    """
     get current mode of card
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :return:
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(modeget,card)

    return devinfo(card,nlsock)['mode']

def devadd(card,vdev,mode,flags=None,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     adds a virtual interface on device having type mode (iw phy <card.phy>
      interface add <vnic> type <mode>
     :param card: Card object
     :param vdev: device name of new interface
     :param mode: 'name' of mode to operate in (must be one of in {'unspecified'|
     'ibss'|'managed'|'AP'|'AP VLAN'|'wds'|'monitor'|'mesh'|'p2p'}
     :param flags: list of monitor flags (can only be used if vnic is being created in
      monitor mode)
     :param argv: netlink socket at argv[0] (or empty)
     :returns: the new Card
    """
    if mode not in IFTYPES: raise PyRIC.pyric.error(errno.EINVAL,'Invalid mode')
    if flags:
        if mode != 'monitor':
            raise PyRIC.pyric.error(errno.EINVAL,'Can only set flags in monitor mode')
        for flag in flags:
            if flag not in MNTRFLAGS:
                raise PyRIC.pyric.error(errno.EINVAL,'Invalid flag: {0}',format(flag))
    else: flags = []

    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(devadd,card,vdev,mode,flags)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_NEW_INTERFACE,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.phy,nl80211h.NL80211_ATTR_WIPHY)
    nl.nla_put_string(msg,vdev,nl80211h.NL80211_ATTR_IFNAME)
    nl.nla_put_u32(msg,IFTYPES.index(mode),nl80211h.NL80211_ATTR_IFTYPE)
    for flag in flags:
        nl.nla_put_u32(msg,MNTRFLAGS.index(flag),nl80211h.NL80211_ATTR_MNTR_FLAGS)
    nl.nl_sendmsg(nlsock,msg)
    rmsg = nl.nl_recvmsg(nlsock) # success returns new device attributes
    return Card(card.phy,vdev,nl.nla_find(rmsg,nl80211h.NL80211_ATTR_IFINDEX))

def devdel(card,*argv):
    """
     REQUIRES ROOT PRIVILEGES
     deletes the device (dev <card.dev> del
     :param card: Card object
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True on success
     NOTE: the original card is no longer valid (i.e. the phy will still be present but
     the device name and ifindex are no longer 'present' in the system
    """
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(devdel,card)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_DEL_INTERFACE,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.idx,nl80211h.NL80211_ATTR_IFINDEX)
    nl.nl_sendmsg(nlsock,msg)
    nl.nl_recvmsg(nlsock)
    return True

################################################################################
#### FILE PRIVATE                                                           ####
################################################################################

def _hex2mac_(v):
    """:returns: a ':' separated mac address from byte stream v"""
    return ":".join(['{0:02x}'.format(ord(c)) for c in v])

def _issetf_(flags,flag):
    """
      determines if flag is set
      :param flags: current flag value
      :param flag: flag to check
      :return: True if flag is set
     """
    return (flags & flag) == flag

def _setf_(flags,flag):
    """
     sets flag, adding to flags
     :param flags: current flag value
     :param flag: flag to set
     :return: new flag value
    """
    return flags | flag

def _unsetf_(flags,flag):
    """
     unsets flag, adding to flags
     :param flags: current flag value
     :param flag: flag to unset
     :return: new flag value
    """
    return flags & ~flag

def _familyid_(nlsock):
    """
     extended version: get the family id
     :param nlsock: netlink socket
     :returns: the family id of nl80211
     NOTE:
      In addition to the family id, we get:
       CTRL_ATTR_FAMILY_NAME = nl80211\x00
       CTRL_ATTR_VERSION = \x01\x00\x00\x00 = 1
       CTRL_ATTR_HDRSIZE = \x00\x00\x00\x00 = 0
       CTRL_ATTR_MAXATTR = \xbf\x00\x00\x00 = 191
       CTRL_ATTR_OPS
       CTRL_ATTR_MCAST_GROUPS
      but for now, these are not used
    """
    global _FAM80211ID_
    if _FAM80211ID_ is None:
        # family id is not instantiated, do so now
        msg = nl.nlmsg_new(nltype=genlh.GENL_ID_CTRL,
                           cmd=genlh.CTRL_CMD_GETFAMILY,
                           flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
        nl.nla_put_string(msg,nl80211h.NL80211_GENL_NAME,
                          genlh.CTRL_ATTR_FAMILY_NAME)
        nl.nl_sendmsg(nlsock,msg)
        rmsg = nl.nl_recvmsg(nlsock)
        _FAM80211ID_ = nl.nla_find(rmsg,genlh.CTRL_ATTR_FAMILY_ID)
    return _FAM80211ID_

def _ifindex_(dev,*argv):
    """
     gets the ifindex for device
     :param dev: device name:
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: ifindex of device
     NOTE: the ifindex can aslo be found in /sys/class/net/<nic>/ifindex
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(_ifindex_,dev)

    try:
        flag = sioch.SIOCGIFINDEX
        ret = io.io_transfer(iosock,flag,ifh.ifreq(dev,flag))
        return struct.unpack_from(ifh.ifr_ifindex,ret,ifh.IFNAMELEN)[0]
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"error parsing results {0}".format(e))

def _flagsget_(dev,*argv):
    """
     gets the device's flags
     :param dev: device name:
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: device flags
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(_flagsget_,dev)

    try:
        flag = sioch.SIOCGIFFLAGS
        ret = io.io_transfer(iosock,flag,ifh.ifreq(dev,flag))
        return struct.unpack_from(ifh.ifr_flags,ret,ifh.IFNAMELEN)[0]
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"error parsing results {0}".format(e))

def _flagsset_(dev,flags,*argv):
    """
     gets the device's flags
     :param dev: device name:
     :param flags: flags to set
     :param argv: ioctl socket at argv[0] (or empty)
     :returns: device flags after operation
    """
    try:
        iosock = argv[0]
    except IndexError:
        return _iostub_(_flagsset_,dev,flags)

    try:
        flag = sioch.SIOCSIFFLAGS
        ret = io.io_transfer(iosock,flag,ifh.ifreq(dev,flag,[flags]))
        return struct.unpack_from(ifh.ifr_flags,ret,ifh.IFNAMELEN)[0]
    except AttributeError as e:
        raise PyRIC.pyric.error(errno.EINVAL,"Invalid parameter {0}".format(e))
    except struct.error as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"error parsing results {0}".format(e))

def _iftypes_(i):
    """
     wraps the IFTYPES list to handle index errors
     :param i:
     :returns: the string IFTYPE corresponding to i
    """
    try:
        return IFTYPES[i]
    except IndexError:
        return 'Unknown mode ({0})'.format(i)

#### TRANSLATION FUNCTIONS ####

def _iostub_(fct,*argv):
    """
     translates from traditional ioctl <cmd> to extended <cmd>ex
     :param fct: function to translate to
     :param argv: parameters to the function
     :returns: the results of fct
    """
    iosock = io.io_socket_alloc()
    try:
        argv = list(argv) + [iosock]
        return fct(*argv)
    except PyRIC.pyric.error:
        raise # catch and rethrow
    finally:
        io.io_socket_free(iosock)

def _nlstub_(fct,*argv):
    """
     translates from traditional netlink <cmd> to extended <cmd>ex
     :param fct: function to translate to
     :param argv: parameters to the function
     :returns: rresults of fucntion
    """
    nlsock = None
    try:
        nlsock = nl.nl_socket_alloc(timeout=2)
        argv = list(argv) + [nlsock]
        return fct(*argv)
    except PyRIC.pyric.error:
        raise
    finally:
        if nlsock: nl.nl_socket_free(nlsock)

#### NOT USED ####

def _fut_chset(card,ch,chw,*argv):
    """
     set current channel on device (iw phy <card.phy> set channel <ch> <chw>
     :param card: Card object
     :param ch: channel number
     :param chw: channel width oneof {None|'HT20'|'HT40-'|'HT40+'}
     :param argv: netlink socket at argv[0] (or empty)
     :returns: True on success
     uses the newer NL80211_CMD_SET_CHANNEL vice iw's depecrated version which
     uses *_SET_WIPHY however, ATT does not work raise Errno 22 Invalid Argument
    """
    if ch not in channels.channels(): raise PyRIC.pyric.error(errno.EINVAL,"Invalid channel")
    if chw not in channels.CHWIDTHS: raise PyRIC.pyric.error(errno.EINVAL,"Invalid channel width")
    try:
        nlsock = argv[0]
    except IndexError:
        return _nlstub_(_fut_chset,card,ch,chw)

    msg = nl.nlmsg_new(nltype=_familyid_(nlsock),
                       cmd=nl80211h.NL80211_CMD_SET_CHANNEL,
                       flags=nlh.NLM_F_REQUEST | nlh.NLM_F_ACK)
    nl.nla_put_u32(msg,card.phy,nl80211h.NL80211_ATTR_WIPHY)
    nl.nla_put_u32(msg,channels.ch2rf(ch),nl80211h.NL80211_ATTR_WIPHY_FREQ)
    nl.nla_put_u32(msg,channels.CHWIDTHS.index(chw),nl80211h.NL80211_ATTR_WIPHY_CHANNEL_TYPE)
    nl.nl_sendmsg(nlsock,msg)
    nl.nl_recvmsg(nlsock)
    return True
