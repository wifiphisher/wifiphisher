#!/usr/bin/env python
""" libnl provides libnl(ish) functionality

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

Relates similarily to libnl by providing functions handling netlink messages
and sockets. Where possible I have attempted to name the below functions the
same as would be found in libnl to ease any transitions. However, I have taken
liberties with the below as these functions only handle nl80211 generic netlink
messages.

see http://www.carisma.slowglass.com/~tgr/libnl/doc/core.html

Provides access to netlink sockets and messages in a manner similar to libnl.

"""

__name__ = 'libnl'
__license__ = 'GPLv3'
__version__ = '0.0.6'
__date__ = 'May 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

from time import time
from os import getpid,strerror
import struct
import socket
from binascii import hexlify
import PyRIC.pyric, errno
import PyRIC.pyric.net.netlink_h as nlh
import PyRIC.pyric.net.genetlink_h as genlh
from PyRIC.pyric.net.policy import nla_datatype

BUFSZ = 32768 # Generic default buffersize

"""
NETLINK SOCKET
"""

class NLSocket(dict):
    """
     Wrapper around a Netlink socket. Exposes the following properties: (callable
     by '.')
      sock: socket, get only
      fd: file descriptor, get only
      pid: (local) port id, get/set
      grpm: group mask, get/set
      seq: seq. #, get/set
      tx: tx buffer size, get only
      rx: rx buffer size, get only
    """
    def __new__(cls,d=None):
        return super(NLSocket,cls).__new__(cls,dict({} if not d else d))

    def __repr__(self):
        """ :returns: description """
        fmt = "NLSocket(fd: {0}, pid: {1}, grpm: {2}, seq: {3}, tx: {4}, rx: {5})"
        return fmt.format(self.fd,self.pid,self.grpm,self.seq,self.tx,self.rx)

    @property
    def sock(self): return self['sock']

    @property
    def fd(self): return self['sock'].fileno()

    @property
    def tx(self): return self['sock'].getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)

    @tx.setter
    def tx(self,v):
        if v < 128 or v > _maxbufsz_():
            raise PyRIC.pyric.error(errno.EINVAL,"Invalid buffer size")
        self['sock'].setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,v)

    @property
    def rx(self): return self['sock'].getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)

    @rx.setter
    def rx(self,v):
        if v < 128 or v > _maxbufsz_():
            raise PyRIC.pyric.error(errno.EINVAL,"Invalid buffer size")
        self['sock'].setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,v)

    @property
    def pid(self): return self['pid']

    @pid.setter
    def pid(self,v):
        if v < 1: raise PyRIC.pyric.error(errno.EINVAL,"Invalid port id")
        self['pid'] = v

    @property
    def grpm(self): return self['grpm']

    @grpm.setter
    def grpm(self,v): self['grpm'] = v

    @property
    def seq(self): return self['seq']

    @seq.setter
    def seq(self,v):
        if v < 1: raise PyRIC.pyric.error(errno.EINVAL,"Invalid sequence number")
        self['seq'] = v

    @property
    def timeout(self): return self['sock'].gettimeout()

    @timeout.setter
    def timeout(self,v):
        if v and v < 0: raise PyRIC.pyric.error(errno.EINVAL,"Invalid timeout value")
        self['sock'].settimeout(v)

    #### wrap socket functions

    def incr(self):
        """ increments seq num """
        self['seq'] += 1

    def send(self,pkt):
        """
         send data
         :param pkt: data to be sent
         :returns: bytes sent
        """
        return self['sock'].send(pkt)

    def recv(self):
        """ :returns: msg from kernel """
        return self['sock'].recv(self.rx)

    def close(self):
        """ closes the socket """
        if self['sock']: self['sock'].close()
        self['sock'] = self['fid'] = None
        self['pid'] = self['grpm'] = self['seq'] = None
        self['rx'] = self['tx'] = None

def nl_socket_alloc(pid=None,grps=0,seq=None,rx=None,tx=None,timeout=None):
    """
     create a netlink socket
     :param pid: port id
     :param grps: multicast groups mask
     :param seq: initial seq. #
     :param rx: rx buffer size
     :param tx: tx buffer size
     :param timeout: time to block on socket
     :returns: a NLSocket
     NOTE:
      per man socket, the kernel will double the specified rx/tx buffer size and
      the min. size is 128
    """
    # set & validate paramaters
    pid = pid or getpid() + int(time()) # allow multiple sockets on this host
    if pid < 1: raise PyRIC.pyric.error(errno.EINVAL,"Invalid port id")
    seq = seq or int(time())
    if seq < 1: raise PyRIC.pyric.error(errno.EINVAL,"Invalid sequence number")
    rx = rx or BUFSZ
    if rx < 128 or rx > _maxbufsz_(): raise PyRIC.pyric.error(errno.EINVAL,"Invalid rx size")
    tx = tx or BUFSZ
    if tx < 128 or tx > _maxbufsz_(): raise PyRIC.pyric.error(errno.EINVAL,"Invalid tx size")

    # create the socket and rturn it
    try:
        s = socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,nlh.NETLINK_GENERIC)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,tx)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,rx)
        s.settimeout(timeout)
        s.bind((pid,grps))
    except socket.error as e:
        raise PyRIC.pyric.error(e.errno,e.strerror)
    return NLSocket({'sock':s,'tx':tx,'rx':rx,'pid':pid,'grpm':grps,'seq':seq})

def nl_socket_free(sock):
    """ close the socket """
    try:
        sock.close()
    except AttributeError: # sock already closed
        pass
    return None

def nl_socket_pid(sock):
    """ :returns netlink socket's pid """
    return sock.pid

def nl_socket_grpmask(sock):
    """ :returns netlink socket's group mask """
    return sock.grpm

def nl_sendmsg(sock,msg,override=False):
    """
      sends msg to kernel
      :param sock: netlink socket
      :param msg: nlmsg stream
      :param override: if True will keep the message's pid and seq. This can
      be used for testing
    """
    try:
        # change the msg's pid & seq to that of the sockets prior to sending &
        # set the ack flag - I can't figure how to tell in recv if the an ack was
        # requested or not so I force an ACK here
        if not override:
            msg.pid = sock.pid
            msg.seq = sock.seq
        msg.flags = msg.flags | nlh.NLM_F_ACK
        sent = sock.send(msg.tostream())
        if sent != msg.len:
            raise PyRIC.pyric.error(errno.EBADMSG,"Message sent incomplete")
    except socket.error as e:
        raise PyRIC.pyric.error(errno.ECOMM, e)
    except AttributeError:
        raise PyRIC.pyric.error(errno.ENOTSOCK, "Invalid netlink socket")

def nl_recvmsg(sock):
    """
     :param sock: netlink socket
     :returns: a GENLMsg received from the socket
    """
    try:
        # pull of the message and following ack message
        # NOTE: nlmsg_fromstream will throw an exception if msg is an ack/nack
        # catch it and test for ack. If it was an ack, return the success code
        # otherwise, reraise it. If it wasn't an ack/nack, return the message
        msg = nlmsg_fromstream(sock.recv())
        try:
            _ = nlmsg_fromstream(sock.recv())
        except PyRIC.pyric.error as e:
            if e.errno == nlh.NLE_SUCCESS: pass
            else: raise
        if sock.seq != msg.seq:
            raise PyRIC.pyric.error(errno.EBADMSG,"seq. # out of order")
        return msg
    except socket.timeout:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"socket timed out")
    except socket.error as e:
        raise PyRIC.pyric.error(errno.ENOTSOCK,e)
    except PyRIC.pyric.error as e:
        if e.errno == nlh.NLE_SUCCESS: return nlh.NLE_SUCCESS
        raise # rethrow
    finally:
        # always increment the sequence #
        sock.incr()

"""
NETLINK MESSAGES

generic netlink data exchanged between user and kernel space is a netlink message
of type NETLINK_GENERIC using the netlink attributes interface. Messages are in
the format:

  <------- NLMSG_ALIGN(hlen) ------> <---- NLMSG_ALIGN(len) --->
 +----------------------------+-----+---------------------+-----+
 |           Header           | Pad |       Payload       | Pad |
 |      struct nlmsghdr       |     |                     |     |
 +----------------------------+-----+---------------------+-----+

  <-------- GENL_HDRLEN -------> <--- hdrlen -->
                                 <------- genlmsg_len(ghdr) ------>
 +------------------------+-----+---------------+-----+------------+
 | Generic Netlink Header | Pad | Family Header | Pad | Attributes |
 |    struct genlmsghdr   |     |               |     |            |
 +------------------------+-----+---------------+-----+------------+

 <-------- nla_attr_size(payload) --------->
 +------------------+-----+------------------+-----+
 | Attribute Header | Pad |     Payload      | Pad |
 +------------------+-----+------------------+-----+

Example: nlmsg for retrieving the family id of nl80211
 |<----------- nlmsghdr ---------->|gemsghdr|<-------- attr -------->|
 |                                          |< hdr >|<--- payload -->|
 | 0 1 2 3 4 5 6 7| 0 1 2 3 4 5 6 7| 0 1 2 3 4 5 6 7| 0 1 2 3 4 5 6 7|
 |2000000010000500|02000000626b0000|030100000c000200|6e6c383032313100|

Netlink message components are aligned on boundaries of 4
"""

"""
The GENLMsg class. There are two methods of creating a GENLMsg:
 1) nlmsg_new -> create a new 'default' msg
 2) nlmsg_fromstream -> create a msg from a string

NOTE: regardles of the message's specified port id & seq #, when sending they
 will be set to that of the socket's port id & seq #. The can be set during
 creation IOT facilitate testing etc
"""

class GENLMsg(dict):
    """
     A wrapper around dict for an underlying generic netlink message of nl80211
     family. Exposes the following properties: (callable by '.')
      len: message length, get only
      nltype: netlink type, get/set
      flags: message flags, get/set
      seq: seq. #, get/set
      pid: port id, get/set
      cmd: etlink command, get/set
      attrs: message attributes get only
     Each attributes is a tuple t = (attribute,value,datatype)
      attribute: netlink type of attribute like CTRL_ATTR_FAMILY_ID
      value: actual value (i.e. unpacked)
      datatype: datatype of attribute value as defined in netlink_h i.e. NLA_U8
     and are sent in the order they are put on the attr list
    """
    def __new__(cls,d=None):
        return super(GENLMsg,cls).__new__(cls,dict({} if not d else d))

    def __repr__(self):
        fmt = "nlmsghdr(len={0},type={1},flags={2},seq={3},pid={4})\n"
        ret = fmt.format(self.len,self.nltype,self.flags,self.seq,self.pid)
        ret += "genlmsghdr(cmd={0})\n".format(self.cmd)
        ret += "attributes:\n"
        for i,(a,v,d) in enumerate(self.attrs):
            if d == nlh.NLA_UNSPEC:
                # getting character(s) in some bytestrings that cause the
                # terminal to hang (why?) hexlify to avoid this
                v = hexlify(v)
            elif d == nlh.NLA_NESTED:
                v = [hexlify(vi) for vi in v]
            ret += "\t{0}: type={1},datatype={2}\n\tvalue={3}\n".format(i,a,d,v)
        return ret

    #### PROPERTIES

    @property # length (inlcuding padding and headers)
    def len(self): return len(self.tostream())

    @property
    def vers(self): return 1

    @property
    def nltype(self): return self['type']

    @nltype.setter
    def nltype(self,v):
        if v < 0: raise PyRIC.pyric.error(errno.ERANGE,"nltype {0} is invalid".format(v))
        self['type'] = v

    @property
    def flags(self): return self['flags']

    @flags.setter
    def flags(self,v): self['flags'] = v

    @property
    def seq(self): return self['seq']

    @seq.setter
    def seq(self,v):
        if v < 1: raise PyRIC.pyric.error(errno.ERANGE,"invalid seq. number")
        self['seq'] = v

    @property
    def pid(self): return self['pid']

    @pid.setter
    def pid(self,v):
        if v < 1: raise PyRIC.pyric.error(errno.ERANGE,"invalid port id")
        self['pid'] = v

    @property
    def cmd(self): return self['cmd']

    @cmd.setter
    def cmd(self,v):
        if v < 0: raise PyRIC.pyric.error(errno.ERANGE,"invalid cmd")
        self['cmd'] = v

    @property
    def attrs(self): return self['attrs']

    @property
    def numattrs(self): return len(self['attrs'])

    #### METHODS

    def tostream(self):
        """ :returns packed netlink message """
        payload = genlh.genlmsghdr(self['cmd'])  # nlhsghdr, genlmsghdr end at boundary of 4
        for attr,v,data in self['attrs']:
            try:
                payload += _attrpack_(attr,v,data)
            except struct.error:
                raise PyRIC.pyric.error(pyric.EUNDEF,"Packing {0} {1}".format(attr,v))
        return nlh.nlmsghdr(len(payload),self.nltype,self.flags,self.seq,self.pid) + payload

def nlmsg_new(nltype=None,cmd=None,seq=None,pid=None,flags=None,attrs=None):
    """
     :param nltype: message content
     :param cmd: genetlink service type
     :param seq: sequence number
     :param pid: port id
     :param flags: additional flags
     :param attrs: attr list list of tuples t = (attribute,value,attr_datatype)
      attribute = netlinke type of attribute like CTRL_ATTR_FAMILY_ID
      value = actual value (i.e. unpacked)
      attr_datatype = type of attribute value as defined in netlink_h i.e. NLA_U8
     :returns a GENLMsg
     NOTE:
      # version is hardcoded as 1 and len is calculated
    """
    return GENLMsg({'type':nltype or nlh.NETLINK_GENERIC,
                    'flags':flags or (nlh.NLM_F_REQUEST|nlh.NLM_F_ACK),
                    'seq':seq or int(time()),
                    'pid':pid or getpid(),
                    'cmd':cmd or genlh.CTRL_CMD_UNSPEC,
                    'attrs':attrs or []})

def nlmsg_fromstream(stream):
    """
     create a GENLMsg from a stream
     :param stream: packed binary data
     :returns: a GENLMsg
    """
    # parse out netlink/generic netlink headers
    try:
        l,t,fs,s,p = struct.unpack_from(nlh.nl_nlmsghdr,stream,0)
        if t == nlh.NLMSG_ERROR or l == nlh.NLMSGACKLEN:
            # have an (possible) ack/nack i.e. error msg
            e = struct.unpack_from(nlh.nl_nlmsgerr,stream,nlh.NLMSGHDRLEN)[0]
            # here is a big problem report NLE_* or errno?
            raise PyRIC.pyric.error(abs(e),strerror(abs(e)))
        c,_,_ = struct.unpack_from(genlh.genl_genlmsghdr,stream,nlh.NLMSGHDRLEN)
    except struct.error as e:
        raise PyRIC.pyric.error(pyric.EUNDEF,"error parsing headers: {0}".format(e))

    # create a new message with hdr values then parse the attributes
    msg = nlmsg_new(t,c,s,p,fs)
    nla_parse(msg,l,t,stream,nlh.NLMSGHDRLEN + genlh.GENLMSGHDRLEN)
    return msg

def nla_parse(msg,l,mtype,stream,idx):
    """
     parses attributes in stream, putting them in msg
     :param msg: current message
     :param l: total length of message
     :param mtype: message content
     :param stream: byte stream
     :param idx: current index in stream
    """
    # get policy family NOTE: cheating here, we know it's either generic or nl80211
    pol = 'ctrl_attr' if mtype == nlh.NETLINK_GENERIC else 'nl80211_attr'
    attrlen = nlh.NLATTRHDRLEN # pull out these to avoid
    attrhdr = nlh.nl_nlattrhdr # doing so in each iteration

    # eat the stream until the end
    while idx < l:
        a = atype = alen = None  # shut pycharm up about unitialized variable
        try:
            alen,atype = struct.unpack_from(attrhdr,stream,idx)  # get length, type
            idx += attrlen               # move to attr start
            alen -= attrlen              # attr length (w/ padding)
            a = stream[idx:idx+alen]     # attr value
            dt = nla_datatype(pol,atype) # attr datatype

            # Note: we use unpack_from which will ignore the null bytes in numeric
            # datatypes & for strings & unspec we just strip trailing null bytes
            if dt == nlh.NLA_STRING or dt == nlh.NLA_UNSPEC: a = _nla_strip_(a)
            if dt == nlh.NLA_NESTED: a = nla_parse_nested(a)
            elif dt == nlh.NLA_U8: a = struct.unpack_from("B",a,0)[0]
            elif dt == nlh.NLA_U16: a = struct.unpack_from("H",a,0)[0]
            elif dt == nlh.NLA_U32: a = struct.unpack_from("I",a,0)[0]
            elif dt == nlh.NLA_U64: a = struct.unpack_from("Q",a,0)[0]
            elif dt == nlh.NLA_FLAG: a = ''  # flags should be 0 size
            elif dt == nlh.NLA_MSECS: a = struct.unpack_from("Q",a,0)[0]
            nla_put(msg,a,atype,dt)
        except struct.error:
            # append as Error, stripping null bytes
            nla_put(msg,_nla_strip_(a),atype,nlh.NLA_ERROR)
        idx = nlh.NLMSG_ALIGN(idx + alen)  # move index to next attr

def nla_parse_nested(nested):
    """
     :param nested: the nested attribute with attribute header removed
     :returns: list of 'packed' nested attributes after length and padding are
      stripped - Callers must parse these themselves
     NOTE: experimental ATT still determining if nl80211 has taken some
      propietary treament(s) of nested attributes or if this is how nested
      attributes should be handled

     From nl80211.h
      @NL80211_ATTR_SUPPORTED_IFTYPES: nested attribute containing all
      supported interface types, each a flag attribute with the number
      of the interface mode.
     and from libnl (Thomas Graf)
      When nesting attributes, the nested attributes are included as payload of
      a container attribute. Attributes are nested by surrounding them with calls
      to nla_nest_start() and nla_nest_end().

       <-------- nla_attr_size(payload) --------->
       +------------------+-----+------------------+-----+
       | Attribute Header | Pad |     Payload      | Pad |
       +------------------+-----+------------------+-----+

     Looking at nl80211 nested attributes, it appears that inside the payload
     there are no dataypes or attribute types, with each nested atrribute as:

      +--------+---------+------+-----+
      | Length | Payload | Null | Pad |
      +--------+---------+------+-----+

     where length is total length of the nested payload exluding the pad bytes.
    """
    ns = []
    idx = 0
    l = len(nested)
    while idx < l:
        # first byte is the length, including this byte and one pad byte - does
        # not include additional pad bytes for proper alignment
        alen = struct.unpack_from('B',nested,idx)[0]
        ns.append(nested[idx+1:idx+(alen-1)])
        idx = nlh.NLMSG_ALIGN(idx + alen)
    return ns

def nla_put(msg,v,a,d):
    """
     append attribute to msg's attribute list
     :param msg: GENLMsg
     :param v: attribute value
     :param a: attribute type
     :param d: attribute datatype
    """
    if d > nlh.NLA_TYPE_MAX: raise PyRIC.pyric.error(errno.ERANGE,"value type is invalid")
    msg['attrs'].append((a,v,d))

# nla_put_* append data of specified datatype
def nla_put_unspec(msg,v,a): nla_put(msg,v,a,nlh.NLA_UNSPEC)
def nla_put_u8(msg,v,a): nla_put(msg,v,a,nlh.NLA_U8)
def nla_put_u16(msg,v,a): nla_put(msg,v,a,nlh.NLA_U16)
def nla_put_u32(msg,v,a): nla_put(msg,v,a,nlh.NLA_U32)
def nla_put_u64(msg,v,a): nla_put(msg,v,a,nlh.NLA_U64)
def nla_put_string(msg,v,a): nla_put(msg,v,a,nlh.NLA_STRING)
def nla_put_msecs(msg,v,a): nla_put(msg,v,a,nlh.NLA_MSECS)
def nla_put_nested(msg,v,a): nla_put(msg,v,a,nlh.NLA_NESTED)

def nla_putat(msg,i,v,a,d):
    """
     puts (overwrites) attribute at index i in msg's attr list
     :param msg: GENLMsg
     :param i: index to put attribute
     :param v: attribute value
     :param a: attribute type
     :param d: attribute datatype
    """
    if d > nlh.NLA_TYPE_MAX: raise PyRIC.pyric.error(errno.ERANGE,"invalid datatype")
    msg['attrs'][i] = (a,v,d)

def nla_pop(msg,i):
    """
     pop and return the attr tuple at i in msg's attr list
     :param msg: GENLMsg
     :param i: index to pop
     :returns: the 'popped' attribute
    """
    attr = msg.attrs[i]
    del msg['attrs'][i]
    return attr

def nla_find(msg,a,value=True):
    """
     find the first attribute having type a in msg's attr list
     :param msg: GENLMsg
     :param a: attribute
     :param value: {True=return attr. value only|False=return attr. triple}
     :returns: first attribute found with a or None
    """
    for t,v,d in msg.attrs:
        if t == a:
            if value: return v
            else: return t,v,d
    return None

def nla_get(msg,i,value=True):
    """
     get attribute at index i in msg's attribute list
     :param msg: GENLMsg
     :param i: index of desired attribute
     :param value: {True=return attr. value only|False=return attr. triple}
     :returns: attribute at i
    """
    attr = msg.attrs[i]
    if value: return attr[1]
    else: return attr

#### FILE PRIVATE ####

def _nla_strip_(v):
    """
     strips padding from v
     :param v: value to strip
     :returns: v w/o padding
     **NOTE: Do not use on numeric attributes
    """
    try:
        for i,e in reversed(list(enumerate(v))):
            if e != '\x00': return v[:i+1]
        return v
    except IndexError:
        return v


def _attrpack_(a,v,d):
    """
     :param a: attribute type
     :param v: value to pack
     :param d: datatype of value
     :returns: packed attribute w/ padding if necessary
    """
    attr = "" # appease PyCharm
    if d == nlh.NLA_UNSPEC: attr = v
    elif d == nlh.NLA_U8: attr = struct.pack("B",v)
    elif d == nlh.NLA_U16: attr = struct.pack("H",v)
    elif d == nlh.NLA_U32: attr = struct.pack("I",v)
    elif d == nlh.NLA_U64: attr = struct.pack("Q",v)
    elif d == nlh.NLA_STRING: attr = struct.pack("{0}sx".format(len(v)),v)
    elif d == nlh.NLA_FLAG: attr = '' # a 0 sized attribute
    elif d == nlh.NLA_MSECS: attr = struct.pack("Q",v)
    elif d == nlh.NLA_NESTED:
        attr = ''
        for nested in v:
            nlen = len(v) + 2
            nattr = struct.pack('B',nlen) + nested + '\x00'
            nattr += struct.pack("{0}x".format(nlh.NLMSG_ALIGNBY(len(nattr))))
            attr += nattr
    attr = nlh.nlattrhdr(len(attr),a) + attr
    # this is nlmsg_padlen
    attr += struct.pack("{0}x".format(nlh.NLMSG_ALIGNBY(len(attr))))
    return attr

def _maxbufsz_():
    """ :returns: maximum allowable socket buffer size """
    fin = None
    try:
        fin = open('/proc/sys/net/core/rmem_max')
        return int(fin.read().strip()) / 2
    except (IOError,ValueError):
        # return a hardcoded value
        return 2097152
    finally:
        if fin: fin.close()
