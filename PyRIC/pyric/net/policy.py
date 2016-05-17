#!/usr/bin/env python
""" attributes defines netlink attribute policies and functions.

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

For lack of a better place to put these, this defines attribute datatypes from
genetlink.h and imports those defined in nl80211_c.

NOTE: I only use the datatype ignoring minlength, maxlength

"""

__name__ = 'attributes'
__license__ = 'GPLv3'
__version__ = '0.0.2'
__date__ = 'April 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import PyRIC.pyric.net.netlink_h as nlh
import PyRIC.pyric.net.genetlink_h as genlh
import PyRIC.pyric.net.wireless.nl80211_c as nl80211c

def nla_datatype(policy,attr):
    """
     determines the appropriate attribute datatype as found in policy
     :param policy: policy name
     :param attr: attribute type
     :returns: a datatype as specified in netlink_h
     NOTE: will return NLA_UNSPEC if given attr can not be found in policy
    """
    try:
        return nla_dts[policy][attr]
    except (KeyError,IndexError):
        return nlh.NLA_UNSPEC

# map string names to datatype lists
nla_dts = {}

#### CTRL_ATTR_*
nla_dts["ctrl_attr"] = {genlh.CTRL_ATTR_UNSPEC:nlh.NLA_UNSPEC,
                        genlh.CTRL_ATTR_FAMILY_ID:nlh.NLA_U16,
                        genlh.CTRL_ATTR_FAMILY_NAME:nlh.NLA_STRING,
                        genlh.CTRL_ATTR_VERSION:nlh.NLA_U32,
                        genlh.CTRL_ATTR_HDRSIZE:nlh.NLA_U32,
                        genlh.CTRL_ATTR_MAXATTR:nlh.NLA_U32,
                        genlh.CTRL_ATTR_OPS:nlh.NLA_NESTED,
                        genlh.CTRL_ATTR_MCAST_GROUPS:nlh.NLA_NESTED}

#### CTRL_ATTR_OP_*
nla_dts["ctrl_attr_op"] = {genlh.CTRL_ATTR_OP_UNSPEC:nlh.NLA_UNSPEC,
                           genlh.CTRL_ATTR_OP_ID:nlh.NLA_U32,
                           genlh.CTRL_ATTR_OP_FLAGS:nlh.NLA_U32}

#### CTRL_ATTR_MCAST_*
nla_dts["ctrl_attr_mcast"] = {genlh.CTRL_ATTR_MCAST_GRP_UNSPEC:nlh.NLA_UNSPEC,
                              genlh.CTRL_ATTR_MCAST_GRP_NAME:nlh.NLA_STRING,
                              genlh.CTRL_ATTR_MCAST_GRP_ID:nlh.NLA_U32}

nla_dts["nl80211_attr"] = nl80211c.nl80211_policy

# ATT we do include the below
#nla_dts["nl80211_key"] = nl80211c.nl80211_key_policy
#nla_dts["nl80211_wowlan_trig"] = nl80211_wowlan_trig_policy
#nla_dts["nl80211_wowlan_tcp"] = nl80211_wowlan_tcp_policy
#nla_dts["nl80211_coalesce"] = nl80211_coalesce_policy
#nla_dts["nl80211_rekey"] = nl80211_rekey_policy
#nla_dts["nl80211_match"] = nl80211_match_policy
#nla_dts["nl80211_plan"] = nl80211_plan_policy
