# PyRIC: Python Radio Interface Controller
## Pythonic iw

## 1 DESCRIPTION:
BLUF: Stop using subprocess.Popen, regular expressions and str.find. PyRIC
is a python port of a subset of iw and python port of netlink (w.r.t nl80211
functions). It arose out of a need in Wraith (https://github.com/wraith-wireless/wraith)
for Python nl80211/netlink and ioctl functionality in Python. Originally, Wraith
used ifconfig, iwconfig and iw via subprocess.Popen and parsed the output. There
are obvious shortfalls with this method, especially in terms of iw that is actively
changing (revisions break the parser) and I started looking for open source
alternatives. There are several open source projects out there like pyroute, pymnl
(and the python files included in the libnl source) but they generally have either
not been maintained recently or come with warnings. I desired a simple interface
to the underlying nl80211 kernel support that handles the complex operations of
netlink seamlessy while maintaining a minimum of "code walking" to understand,
modify and add future operations. I decided to write my own because I do not need
complete netlink functionality, only that provided by generic netlink and within
the nl80221 family. Additionally, for Wraith, I do not need a full blown port of
iw (and ifconfig, iwconfig) functionality to Python but only require the ability
to turn a wireless nic on/off, get/set the hwaddr, get/set the channel, determine
some properties of the card and add/delete interfaces.

So, why did I do this? When I first started to explore the idea of moving away
from iw output parsing, I looked at the source for iw, and existing Python ports.
Just to figure out how to get the family id for nl80211 required reading through
five different source files with no comments. To that extent, I have attempted to
keep subclassing to a minimum, the total number of classes to a minimum, combine
files where possible and where it makes since and keep the number of files required
to be open simulateneously in order to understand the methodology and follow the
program to a minimum. One can understand the PyRIC program flow with only two files
open at any time namely, pyw and libnl. In fact, only an understanding of pyw is
required to add additional commands although an understanding of libnl is helpful
especially, if for example, the code is to be extended to handle multicast or
callbacks.

In addition to providing some ifconfig functionality, I have also added several
"extensions" to iw:
* Persistent sockets: PyRIC provides the caller with functions & ability to pass 
their own netlink (or ioctl socket) to pyw functions;
* One-time request for the nl80211 family id.
While minimal, they will slightly improve the performance of any programs that
needs to access the wireless network interface repeatedly.

ATT, PyRIC accomplish my core needs but it is still a work in progress. It provides
the following:
* enumerate interfaces and wireless interfaces
* identify a cards chipset and driver
* get/set hardware address
* turn card on/off
* get supported standards
* get supported commands
* get supported modes
* get dev info
* get phy info (does not currently process the bands)
* get/set regulatory domain
* get info on a device
* add/delete interfaces

It also provides limited help functionality concerning nl80211 commands/attributes.
However, it pulls directly from the nl80211 header file.

### a. PyRIC Functionality

What it does - defines programmatic access to a small subset of iw and ifconfig.

What it does not do - handle multicast messages, callbacks or dumps, attributes
or non nl80211 funtionality.

## 2. INSTALLING/USING:

Starting with version 0.0.6, the structure (see Section 4) has changed to facilitate 
packaging on PyPI. This restructing has of course led to some minor difficulties 
especially when attempting to install (or even just test) outside of a pip installation.

### a. Requirements
PyRIC has only two requirements: Linux and Python. ATT however, there has been very
little testing on kernel 4.x and Python 3 while working out the small bugs continues
on Python 2.7 and kernel 3.13.x.

### b. Install from Package Manager
Obviously, the easiest way to install PyRIC is through PyPI:

    sudo pip install --pre PyRIC

Note the use of the '--pre' flag. Without it, pip will not install PyRIC since it
is still in the developmental stage.

### c. Install from Source
The PyRIC source (tarball) can be downloaded from https://pypi.python.org/pypi/PyRIC or 
http://wraith-wireless.github.io/PyRIC. Additionally, the source, as a zip file, can be 
downloaded from https://github.com/wraith-wireless/PyRIC. Once downloaded, extract the 
files and from the PyRIC directory run:

    sudo python setup.py install

### d. Test without Installing

If you just want to test PyRIC out, download your choice from above. After extraction, move
the pyric folder (the package directory) to your location of choice and from here start Python
and import pyw. It is very important that you do not try and run it from PyRIC which is the 
distribution directory. This will break the imports pyw uses.

You will only be able to test PyRIC from the pyric directory but, if you want to, you can
add it to your Python path and run it from any program or any location. To do so, assume you
untared pyric to /home/bob/pyric. Create a text file named pyric.pth with one line

    /home/bob/pyric

save this file to /usr/lib/python2.7/dist-packages (or /usr/lib/python3/dist-packages if you
want to try it in Python 3). 

https://github.com/wraith-wireless/pyric/releases/ or https://pypi.python.org/pypi/PyRIC/
untar and run from the downloaded package directory (pyric/pyric.

### e. Stability vs Latest

Keep in mind that the most stable version, easist install and oldest release is on PyPI (install 
through pip or download through PyPI). The source on http://wraith-wireless.github.io/PyRIC tends 
to be newer but may have some bugs and the most recent source, hardest to install is on
https://github.com/wraith-wireless/pyric/releases/ but may not be stable and may in fact not run 
at all.

### f. Using
Once installed, see examples/pentest.py which covers most pyw functions or read PyRIC.pdf. However, 
for those impatient types:

```python
import pyric
from pyric import pyw
```

** 3. EXTENDING:

Extending PyRIC is fun and easy too, see the user guide PyRIC.pdf.

## 4. ARCHITECTURE/HEIRARCHY: Brief Overview of the project file structure

* pyric                   root Distribution directory
  - \_\_init\_\_.py       initialize 'outer' pyric module
  - examples              example folder
    + pentest.py          create wireless pentest environment example
  - setup.py              install file
  - setup.cfg             used by setup.py
  - MANIFEST.in           used by setup.py
  - README.md             this file
  - LICENSE               GPLv3 License
  * PyRIC.pdf             User Guide
  - pyric                 package directory
    + \_\_init\_\_.py     initialize pyric module
    + pyw.py              wireless nic functionality
    + radio.py            consolidate pyw in a class
    + channels.py         802.11 ISM/UNII freqs. & channels
    + device.py           device/chipset utility functions
    + TODO                todos for PyRIC
    + RFI                 comments and observations
    + net                 linux header ports
      * \_\_init\_\_.py   initialize net subpackage
      * if_h.py           inet/ifreq definition
      * sockios_h.py      socket-level I/O control calls
      * genetlink_h.py    port of genetlink.h
      * netlink_h.py      port of netlink.h
      * policy.py         defines attribute datatypes
      * wireless          wireless subpackage
        - \_\_init\_\_.py initialize wireless subpackage
        - nl80211_h.py    nl80211 constants
        - nl80211_c.py    nl80211 attribute policies
    + lib                 library subpackages
      * \_\_init\_\_.py   initialize lib subpackage
      * libnl.py          netlink helper functions
      * libio.py          sockios helper functions
    + docs                netlinke documentation/help
      * nlhelp.py         nl80211 search
      * commands.help     nl80211 commands help data
      * attributes.help   nl80211 attributes help data
      * res               User Guide resources
        - PyRIC.tex       User Guide LaTex
        - PyRIC.bib       User Guide bibliography
