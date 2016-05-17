#!/usr/bin/env python
""" lib lib subpackage

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

lib subpackage

 lib 0.0.2
  desc: lib subpackage
 includes: libnl 0.0.6 libio 0.0.1
 changes:
  o added libio
  o updated libnl
   - added nlmsg_fromstream
   - added NLSocket class
   - added partial support of nested attributes
  o added functionality to modify rx,tx and timeout after socket creation
  o update libnl.py
   - remove nla_* from GENLMsg stand-alone functions as this was my original
    intent where the classes should only be 'placeholders', similar to C structs
    and not full blow objects
"""

__name__ = 'lib'
__license__ = 'GPLv3'
__version__ = '0.0.2'
__date__ = 'April 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'