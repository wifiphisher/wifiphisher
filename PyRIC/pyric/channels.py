#!/usr/bin/env python

""" channels.py: 802.11 channel/freq utilities

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

Only defines ISM 2.4Ghz and UNII 5Ghz

"""

__name__ = 'channels'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'August 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import PyRIC.pyric.net.wireless.nl80211_h as nl80211h

# redefined widths (allowed in nl80211h)
CHWIDTHS = nl80211h.NL80211_CHAN_WIDTHS

# ISM Bands
ISM_24_C2F={1:2412,2:2417,3:2422,4:2427,5:2432,6:2437,7:2442,
            8:2447,9:2452,10:2457,11:2462,12:2467,13:2472,14:2484}
ISM_24_F2C={2432:5,2467:12,2437:6,2472:13,2442:7,2484:14,2412:1,
            2447:8,2417:2,2452:9,2422:3,2457:10,2427:4,2462:11}

# UNII 5 Bands
UNII_5_C2F={36:5180,38:5190,40:5200,42:5210,44:5220,46:5230,48:5240,52:5260,
            56:5280,60:5300,64:5320,100:5500,104:5520,108:5540,112:5560,116:5580,
            120:5600,124:5620,128:5640,132:5660,136:5680,140:5700,149:5745,
            153:5765,157:5785,161:5805,165:5825}
UNII_5_F2C={5765:153,5640:128,5260:52,5520:104,5785:157,5660:132,5280:56,
            5540:108,5805:161,5680:136,5300:60,5560:112,5180:36,5825:165,
            5700:140,5190:38,5320:64,5580:116,5200:40,5210:42,5600:120,
            5220:44,5230:46,5745:149,5620:124,5240:48,5500:100}

# UNII 4 Bands
#UNII_4_C2F={183:4915,184:4920,185:4925,187:4935,188:4940,189:4945,192:4960,196:4980}
#UNII_4_F2C={4960:192,4935:187,4940:188,4945:189,4915:183,4980:196,4920:184,4925:185}

def channels():
    """ :returns: list of all channels """
    return sorted(ISM_24_C2F.keys() + UNII_5_C2F.keys())

def freqs():
    """ :returns: list of frequencies """
    return sorted(ISM_24_F2C.keys() + UNII_5_F2C.keys())

def ch2rf(c):
    """
     channel to frequency conversion

     :param c: channel
     :returns: frequency in MHz corresponding to channel
    """
    if c in ISM_24_C2F: return ISM_24_C2F[c]
    if c in UNII_5_C2F: return UNII_5_C2F[c]
    return None

def rf2ch(f):
    """
     frequency to channel conversion

     :param f: frequency (in MHz)
     :returns: channel number corresponding to frequency
    """
    if f in ISM_24_F2C: return ISM_24_F2C[f]
    if f in UNII_5_F2C: return UNII_5_F2C[f]
    return None
