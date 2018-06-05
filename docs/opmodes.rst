Modes of operation
==================

Wifiphisher comes with an algorithm for allocating and utilizing the running
system's physical cards in an optimal way. This algorithm is executed in an
early stage, during the initialization of the Wifiphisher engine. As a result,
Wifiphisher main engine will operate in a mode (OPMODE) with a specific set of
features. 

There are different processes spawned from within Wifiphisher main procedure
that take advantage of a wireless interface in a different Wi-Fi mode.

- Roguehostapd needs a wireless interface operating in AP-mode to spawn the rogue Access Point.
- Extension Manager (EM) needs a wireless interface operating in Monitor mode to read and write raw 802.11 frames. Channel hopping or Station Operations may or may not be enabled.
- Wireless Station needs a wireless interface operating in Managed mode to connect (or attempt to connect) to Wi-Fi networks in order to provide Internet connectivity.


Not all of the above processess run on every Wifiphisher instance. For example,
using the default options, a wireless station is never utilized or by using the
`--noextensions` option, EM is never spawned.

The wireless interfaces may or may not correspond directly to a physical card.
If there are not enough wireless interfaces, Wifiphisher will spawn a virtual
interface (vif) out of a physical card if that card allows it. The main
challenge here is that two virtual interfaces spawned from the same wireless
card may not operate in different channels. This may complicate things, e.g. if
there is only one physical card on the system, EM will not perform any channel
hopping.

Following are all the opmodes along with their conditions.

OPMODE 0x01
-----------

Features:

- [x] Evil Twin
- [x] Extensions
- [ ] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [ ] Internet

Conditions

If there is one available physical card, that supports AP-mode and Monitor mode
or if the user requests it via arguments (e.g. using --interface).

OR

There are two available physical cards:

- one card supports Monitor Mode
- another card supports AP mode

OPMODE 0x02
-----------

Features:

- [x] Evil Twin
- [x] Extensions
- [x] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [ ] Internet

Conditions:

There are two available physical cards:

- one card supports Monitor Mode
- another card supports AP mode

OPMODE 0x03
-----------

Features:

- [x] Evil Twin
- [x] Extensions
- [ ] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [x] Internet

Conditions:

* Conditions for OPMODE 0x01 are satisfied
* There is a second card that supports STA

OPMODE 0x04
-----------

Features:

- [x] Evil Twin
- [x] Extensions
- [x] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [x] Internet

Conditions:

* Conditions for OPMODE 0x02 are satisfied
* There is a third card that supports STA

OPMODE 0x05
-----------

- [x] Evil Twin
- [ ] Extensions
- [ ] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [ ] Internet


Conditions:

If there is one available physical card:
- that supports Access Point mode and it is not possible to spawn a second vif 
or if the user requests it via arguments (e.g. using --noextensions)

OPMODE 0x06
-----------

- [x] Evil Twin
- [ ] Extensions
- [ ] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [x] Internet

Conditions:

* Conditions for OPMODE 0x05 are satisfied
* There is a second card that supports STA

OPMODE 0x07
-----------

- [x] Evil Twin
- [x] Extensions
- [x] Extensions w/ channel hopping
- [x] Extensions w/ STA capabilities
- [x] Internet

Conditions:

* Conditions for OPMODE 0x04 are satisfied
* There are two additional cards that support STA

OPMODE 0x08
-----------

- [x] Evil Twin
- [x] Extensions
- [ ] Extensions w/ channel hopping
- [x] Extensions w/ STA capabilities
- [ ] Internet

Conditions:

* Conditions for OPMODE 0x04 are satisfied
* There is an additional card that supports STA

OPMODE 0x09
-----------

- [x] Evil Twin
- [x] Extensions
- [x] Extensions w/ channel hopping
- [ ] Extensions w/ STA capabilities
- [x] Internet

Conditions:

* Conditions for OPMODE 0x02 are satisfied
* There is an additional card that supports STA

OPMODE 0x10
-----------

- [x] Evil Twin
- [x] Extensions
- [ ] Extensions w/ channel hopping
- [x] Extensions w/ STA capabilities
- [x] Internet

Conditions:

- Conditions for OPMODE 0x01 are satisfied
- There are two additional cards that support STA
