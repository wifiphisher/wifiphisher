#!/usr/bin/env python
""" pyric Python Radio Interface Controller

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

Defines the Pyric error class and constants for some errors. All pyric errors
will follow the 2-tuple form of EnvironmentError

Requires:
 linux (preferred 3.x kernel)
 Python 2.7
 
 pyric 0.0.2
  desc: wireless nic (radio) manipulation, enumeration, and attribute enumeration
 includes:  /net /lib pyw 0.0.3 radio 0.0.4 utils 0.0.2
 changes:
  o added ifconfig/iwconfig functions to pyw
  o reworked exception handling
   - all exceptions from libnl, libio & pyw are pyric.error
   - pyw will allow pyric to pass through
   - reworked errorcodes to derive from errno
  o added _iostub_, _nlstub_ and reworked traditiona commands to utilize these
  o finished porting nl80211_h and nl80211_c (for attribute policies)
  o pyw no longer provides familyid as a public function, rather it now uses a
    private global value for the nl80211 family id and will instantiate it one
    time only. In this way, callers do not not have to worry about retrieving and
    passing it
  o regdom get & set implemented
  o info implemented

 pyric 0.0.3
  desc: wireless nic (radio) manipulation, enumeration, and attribute enumeration
 includes:  /net /lib pyw 0.0.3 device 0.0.3 channels 0.0.1
 changes:
  o removed radio/Radio class (shouldn't be the responsibility of this)
  o added channels.py (provides channel/freq functions)
  o added RFI page for notes/observations/questions
  o changed utils.py to device.py
  o updated libnl
  o added channel set & get
   - channel get only works when device is associated
   - channel set only works when card is in monitor mode and all other interfaces
    have been deleted
  o added device add & delete

 pyric 0.0.4
  desc: wireless nic (radio) manipulation, enumeration, and attribute enumeration
  includes:  /net /lib pyw 0.1.0 device 0.0.3 channels 0.0.1 setup 0.0.2
  changes:
   o rewrote pyw function to handle one-time & persistent functions using a
    single function interface for each command

 pyric 0.0.5
  desc: wireless nic (radio) manipulation, enumeration, and attribute enumeration
  includes:  /net /lib /docs pyw 0.1.2 device 0.0.3 channels 0.0.1
  changes:
   o added Card class and wrote functions to handle it in pyw
   o implemented basic help functionality (for nl80211)
   o added monitor flag(s) support in devadd
   o began work on a user guide
   o added nested attribute handling
   o added partial phyinfo handles all but supported channels/bands
   o fixed bugs in devinfo and phyinfo
   o added setup.py and required files

 pyric 0.0.6
  desc: Pythonic iw - wireless nic (radio) manipulation, enumeration, and attribute
  enumeration
  includes:  /docs /examples /lib /net pyw 0.1.2 device 0.0.3 channels 0.0.1
  changes:
   o move pyric under pyric to facilitate setuptools and packaging
    - moved LICENSE, MANIFEST.in README.md setup.cfg setup.py examples/ PyRIC.pdf
      to outer pyric
   o at least one card (ath9k_htc) has an unknown supported command, added a
    wrapper around the list IFTYPES to handle commands not listed

 pyric 0.0.7
  desc: Pythonic iw - wireless nic (radio) manipulation, enumeration, and attribute
  enumeration
  includes:  /docs /examples /lib /net pyw 0.1.2 device 0.0.3 channels 0.0.1
  changes:
   o libnl: attribute related i.e. nla_* moved out of GENLMsg class and made as
     standalone functions
   o in pyw
    - added modeset/modeget in pyw
    - readded freqset in pyw
    - added devcmds in pyw
    - annotated (in comments) if fcts needed root privileges
"""

__name__ = 'pyric'
__license__ = 'GPLv3'
__version__ = '0.0.7'
__date__ = 'April 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

from os import strerror

# all exceptions are tuples t=(error code,error message)
# we use errno.errocodes and use codes < 0 as an undefined error code
EUNDEF = -1
class error(EnvironmentError): pass

def perror(e):
    """
    :param e: error code
    :returns: string description of error code
    """
    # anything less than 0 is an unknown
    return strerror(e)

