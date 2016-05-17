#!/usr/bin/env python
""" nlhelp.py: nl80211 help functions

A set of functions to assist in finding info on nl80211 commands and attributes.
These are stored in the "data" files commands.help and attributes.help which are
json files.

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

__name__ = 'nlhelp'
__license__ = 'GPLv3'
__version__ = '0.0.1'
__date__ = 'August 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import os
import json
import PyRIC.pyric
import PyRIC.pyric.net.wireless.nl80211_h as nl80211h

# where are we?
fpath = os.path.dirname(os.path.realpath(__file__))

# read in the files here
cmdpath = os.path.join(fpath,'commands.help')
commands = None   # cmd -> desc,attributes used dict
cmdlookup = None  # reverse lookup for command constants
cin = None
try:
    # first two lines are comments, 3rd line is empty
    cin = open(cmdpath,'r')
    for _ in xrange(3): _in = cin.readline()
    commands = json.loads(cin.readline())
    cmdlookup = json.loads(cin.readline())
except:
    raise PyRIC.pyric.error(pyric.EUNDEF,"Failed to process commands.help")
finally:
    if cin: cin.close()

attrpath = os.path.join(fpath,'attributes.help')
attributes = None # attr -> desc, commands used by, datatype
attrlookup = None # reverse lookup for attribute constants
ain = None
try:
    # first two lines are comments, 3rd line is empty
    ain = open(attrpath,'r')
    for _ in xrange(3): _in = ain.readline()
    attributes = json.loads(ain.readline())
    attrlookup = json.loads(ain.readline())
except:
    raise PyRIC.pyric.error(pyric.EUNDEF, "Failed to process attributes.help")
finally:
    if ain: ain.close()

def command(cmd):
    """
      shows help on command can either be the full name i.e. NL80211_CMD_GET_WIPHY
      or a shortened version GET_WIPHY
     :param cmd: command to show description of.
     :returns: description of command, attributes used in command and the constant
     that refers to the command
    """
    try:
        cmd = cmd.upper().replace('@','') # in the event it comes from cmdbynum
        if not cmd.startswith("NL80211_CMD_"): cmd = "@NL80211_CMD_" + cmd
        else: cmd = '@' + cmd
        entry = commands[cmd]
        attrs = ", ".join([attr.replace('%','') for attr in entry['attrs']])
        out = "{0}\tValue={1}\n".format(cmd,eval('nl80211h.' + cmd[1:]))
        out += "------------------------------------------------------\n"
        out += "Description: {0}\n".format(entry['desc'])
        out += "------------------------------------------------------\n"
        out += "Attributes: {0}".format(attrs)
        return out
    except KeyError:
        return "No entry found for command {0}".format(cmd)
    except AttributeError:
        return "{0} not found in nl80211_h".format(cmd)

def cmdbynum(n):
    """
     reverse lookup n to corresponding command variable
     :param n: integer value to search for
     :returns: string representation of the command variable corresponding to n
    """
    return cmdlookup[str(n)]

def attribute(attr):
    """
     shows help on attribute can either be the full name i.e. NL80211_ATTR_MAC
     or a shortened version MAC
     :param attr: attribute to show description of.
     :returns: description of attribute, commands that use the attribute, datatype
      of the attribute and the constant that refers to the attribute
      """
    try:
        attr = attr.upper().replace('@','')  # in the event it comes from attrbynum
        if not attr.startswith("NL80211_ATTR_"): attr = "@NL80211_ATTR_" + attr
        else: attr = '@' + attr
        entry = attributes[attr]
        cmds = ", ".join([cmd.replace('%', '') for cmd in entry['cmds']])
        out = "{0}\tValue={1}\tDatatype={2}\n".format(attr,
                                                      eval('nl80211h.' + attr[1:]),
                                                      entry['type'])
        out += "------------------------------------------------------\n"
        out += "Description: {0}\n".format(entry['desc'])
        out += "------------------------------------------------------\n"
        out += "Commands: {0}".format(cmds)
        return out
    except KeyError:
        return "No entry found for attribute {0}".format(attr)
    except AttributeError:
        return "{0} not found in nl80211_h".format(attr)

def attrbynum(n):
    """
     reverse lookup n to corresponding attribute variable
     :param n: integer value to search for
     :returns: string representation of the command variable corresponding to n
    """
    return attrlookup[str(n)][0]

def search(tkn):
    """
     searches for and returns any commands,attributes with tkn
     :param tkn:
     :returns: a list of commands,attributes with tkn in them
    """
    tkn = tkn.upper()
    if len(tkn)  < 3:
        raise PyRIC.pyric.error(PyRIC.pyric.EUNDEF,"{0} is to ambiguous".format(tkn))
    found = [cmd for cmd in commands if tkn in cmd]
    found += [attr for attr in attributes if tkn in attr]
    return found
