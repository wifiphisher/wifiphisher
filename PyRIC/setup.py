#!/usr/bin/env python

""" setup.py: install PyRIC

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

"""

#__name__ = 'setup'
__license__ = 'GPLv3'
__version__ = '0.0.2'
__date__ = 'May 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

from setuptools import setup, find_packages
#from codecs import open
#from os import path
import pyric


long_desc = """
A simple interface to the underlying nl80211 kernel support that handles the
complex operations of netlink seamlessy while maintaining a minimum of "code
walking" to understand, modify and add future operations. Not a full blown port
of iw (and ifconfig, iwconfig) functionality to Python but sufficient to
programmatically create a wireless pentest environment"""

setup(name='PyRIC',
      version=pyric.__version__,
      description="PyRIC: python port of a subset of iw",
      long_description=long_desc,
      url='http://wraith-wireless.github.io/pyric',
      download_url="https://github.com/wraith-wireless/pyric/archive/"+pyric.__version__+".tar.gz",
      author=pyric.__author__,
      author_email=pyric.__email__,
      maintainer=pyric.__maintainer__,
      maintainer_email=pyric.__email__,
      license=pyric.__license__,
      classifiers=['Development Status :: 4 - Beta',
                   'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                   'Intended Audience :: Developers',
                   'Topic :: Software Development',
                   'Topic :: Software Development :: Libraries',
                   'Topic :: Security',
                   'Topic :: System :: Networking',
                   'Topic :: Utilities',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: Python'
                   ],
    keywords='nl80211 iw developement wireless pentest',
    packages=find_packages(),
    package_data={'pyric':['docs/*.help']}
)
