#!/usr/bin/env python
""" net

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

Linux header ports for netlink et al.

 net 0.0.2
  desc: linux header ports
 includes: /wireless genetlink_h 0.0.1 if_h 0.0.2 netlink_h 0.0.3 sockios_h 0.0.2
  policy 0.0.2
 changes:
  o added attribute constants to nl80211_h
  o added attributes.py to define nla_policies
  o renamed attributes.py to policy.py to avoid confusion
  o changed policies from list to dict
  o removed nle_error related as we use python errno
"""

__name__ = 'net'
__license__ = 'GPLv3'
__version__ = '0.0.2'
__date__ = 'April 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

