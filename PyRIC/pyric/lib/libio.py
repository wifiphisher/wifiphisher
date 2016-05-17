#!/usr/bin/env python
""" libio provides ioctl socket & send/recv functionality

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

Basic wrappers providing functionality for socket creation/deletion and send/recv
w.r.t ioctl calls

"""

__name__ = 'libio'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'April 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import socket
import struct
import errno
from fcntl import ioctl
import PyRIC.pyric

def io_socket_alloc():
    """
     create a socket for ioctl calls
     :returns: an io socket
    """
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def io_socket_free(sock):
    """ close the socket """
    try:
        sock.close()
    except Exception: # ignore all
        pass
    return None

def io_transfer(iosock,flag,ifreq):
    """
     send & recieve an ifreq struct
     :param iosock: io socket
     :param flag: sockios control call
     :param ifreq: ifreq to send
     :returns: an the ifreq struct recieved
    """
    try:
        return ioctl(iosock.fileno(),flag,ifreq)
    except (AttributeError,struct.error) as e:
        # either sock is not valid or a bad value passed to ifreq
        # note: should not get these but just in case
        if e.message.find('fileno'): raise PyRIC.pyric.error(errno.ENOTSOCK, "bad socket")
        else: raise PyRIC.pyric.error(errno.EINVAL,e)
    except IOError as e:
        # generally device cannot be found sort but can also be
        # permissions etc, catch and reraise as our own
        if e.errno is not None: # just in case we have a none 2-tuple error
            raise PyRIC.pyric.error(e.errno,e.strerror)
        else:
            raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,e)
    except Exception as e:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,e.args[0])
