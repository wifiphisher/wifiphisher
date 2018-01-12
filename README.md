[![Build Status](https://travis-ci.org/wifiphisher/wifiphisher.svg?branch=master)](https://travis-ci.org/wifiphisher/wifiphisher)
[![Documentation Status](https://readthedocs.org/projects/wifiphisher/badge/?version=latest)](http://wifiphisher.readthedocs.io/en/latest/?badge=latest)
![Python Version](https://img.shields.io/badge/python-2.7-blue.svg)
![License](https://img.shields.io/badge/license-GPL-blue.svg)
[![Chat IRC](https://img.shields.io/badge/chat-IRC-ff69b4.svg)](https://webchat.freenode.net/?channels=%23wifiphisher)

<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/wifiphisher.png" /></p>

## About
<a href="https://wifiphisher.org">Wifiphisher</a> is a security tool that performs Wi-Fi automatic association attacks to force wireless clients to unknowingly connect to an attacker-controlled Access Point. It is a rogue Access Point framework that can be used to mount automated victim-customized phishing attacks against WiFi clients in order to obtain credentials or infect the victims with malwares. It can work a social engineering attack tool that unlike other methods it does not include any brute forcing. It is an easy way for obtaining credentials from captive portals and third party login pages (e.g. in social networks) or WPA/WPA2 pre-shared keys.

Wifiphisher works on Kali Linux and is licensed under the GPL license.

## How it works
After achieving a man-in-the-middle position using Wi-Fi automatic association techniques (including "KARMA" and "Known Beacons" attacks), Wifiphisher by default redirects all HTTP requests to an attacker-controlled phishing page.

From the victim's perspective, the attack makes use in three phases:

1. **Victim is being deauthenticated from her access point**. Wifiphisher continuously jams all of the target access point's wifi devices within range by forging “Deauthenticate” or “Disassociate” packets to disrupt existing associations.
2. **Victim joins a rogue access point**. Wifiphisher sniffs the area and copies the target access point's settings. It then creates a rogue wireless access point that is modeled by the target. It also sets up a NAT/DHCP server and forwards the right ports. Consequently, because of the deauth attack and the automatic association techniques, clients will eventually start connecting to the rogue access point. After this phase, the victim is MiTMed. 
3. **Victim is being served a realistic specially-customized phishing page**. Wifiphisher employs a minimal web server that responds to HTTP & HTTPS requests. As soon as the victim requests a page from the Internet, wifiphisher will respond with a realistic fake page that asks for credentials or serves malwares. This page will be specifically crafted for the victim. For example, a router config-looking page will contain the brand of the victim's vendor. The tool supports community-built templates for different phishing scenarios.

<p align="center"><img width="70%" src="https://wifiphisher.github.io/wifiphisher/diagram.jpg" /><br /><i>Performing MiTM attack</i></p>

## Requirements
Following are the requirements for getting the most out of Wifiphisher:

* Kali Linux. Although people have made Wifiphisher work on other distros, Kali Linux is the officially supported distribution, thus all new features are primarily tested on this platform.
* One wireless network adapter that supports AP & Monitor mode and is capable of injection. For advanced mode, you need two cards; one that supports AP mode and another that supports Monitor mode. Drivers should support netlink.

## Installation

To install the latest development version type the following commands:

```bash
git clone https://github.com/wifiphisher/wifiphisher.git # Download the latest revision
cd wifiphisher # Switch to tool's directory
sudo python setup.py install # Install any dependencies
```

Alternatively, you can download the latest stable version from the <a href="https://github.com/wifiphisher/wifiphisher/releases">Releases page</a>.

## Usage

Run the tool by typing `wifiphisher` or `python bin/wifiphisher` (from inside the tool's directory).

By running the tool without any options, it will find the right interfaces and interactively ask the user to pick the ESSID of the target network (out of a list with all the ESSIDs in the around area) as well as a phishing scenario to perform. By default, the tool will perform both Evil Twin and KARMA attacks.

***

```shell
wifiphisher -aI wlan0 -jI wlan4 -p firmware-upgrade --handshake-capture handshake.pcap
```

Use wlan0 for spawning the rogue Access Point and wlan4 for DoS attacks. Select the target network manually from the list and perform the "Firmware Upgrade" scenario. Verify that the captured Pre-Shared Key is correct by checking it against the handshake in the handshake.pcap file.

Useful for manually selecting the wireless adapters. The <a href="https://wifiphisher.org/ps/firmware-upgrade/">"Firmware Upgrade"</a> scenario is an easy way for obtaining the PSK from a password-protected network.

***

```shell
wifiphisher --essid CONFERENCE_WIFI -p plugin_update -pK s3cr3tp4ssw0rd
```

Automatically pick the right interfaces. Target the Wi-Fi with ESSID "CONFERENCE_WIFI" and perform the "Plugin Update" scenario. The Evil Twin will be password-protected with PSK "s3cr3tp4ssw0rd".

Useful against networks with disclosed PSKs (e.g. in conferences). The <a href="https://wifiphisher.org/ps/plugin_update/">"Plugin Update"</a> scenario provides an easy way for getting the victims to download malicious executables (e.g. malwares containing a reverse shell payload).

***

```shell
wifiphisher --noextensions --essid "FREE WI-FI" -p oauth-login -kB
```

Do not load any extensions. Simply spawn an open Wi-Fi network with ESSID "FREE WI-FI" and perform the "OAuth Login" scenario. Use the "Known Beacons" Wi-Fi automatic association technique.

Useful against victims in public areas. The <a href="https://wifiphisher.org/ps/oauth-login/">"OAuth Login"</a> scenario provides a simple way for capturing credentials from social networks, like Facebook. 


Following are all the options along with their descriptions (also available with `wifiphisher -h`):

| Short form | Long form | Explanation |
| :----------: | :---------: | :-----------: |
|-h | --help| show this help message and exit |
|-jI EXTENSIONSINTERFACE| --extensionsinterface EXTENSIONSINTERFACE|	Manually choose an interface that supports monitor mode for running the extensions. Example: -jI wlan1|
|-aI APINTERFACE| --apinterface APINTERFACE|	Manually choose an interface that supports AP mode for spawning an AP. Example: -aI wlan0|
|-nJ| --noextensions|	Do not load any extensions.|
|-e ESSID| --essid ESSID|	Enter the ESSID of the rogue Access Point. This option will skip Access Point selection phase. Example: --essid 'Free WiFi'|
|-p PHISHINGSCENARIO| --phishingscenario PHISHINGSCENARIO	|Choose the phishing scenario to run.This option will skip the scenario selection phase. Example: -p firmware_upgrade|
|-pK PRESHAREDKEY| --presharedkey PRESHAREDKEY|	Add WPA/WPA2 protection on the rogue Access Point. Example: -pK s3cr3tp4ssw0rd|
|-qS| --quitonsuccess|	Stop the script after successfully retrieving one pair of credentials.|
|-lC| --lure10-capture| Capture the BSSIDs of the APs that are discovered during AP selection phase. This option is part of Lure10 attack.
|-lE LURE10_EXPLOIT |--lure10-exploit LURE10_EXPLOIT| Fool the Windows Location Service of nearby Windows users to believe it is within an area that was previously captured with --lure10-capture. Part of the Lure10 attack.|
|-iAM| --mac-ap-interface| Specify the MAC address of the AP interface. Example: -iAM 38:EC:11:00:00:00|
|-iEM| --mac-extensions-interface| Specify the MAC address of the extensions interface. Example: -iEM E8:2A:EA:00:00:00|
|-iNM| --no-mac-randomization| Do not change any MAC address.|
|-hC|--handshake-capture|Capture of the WPA/WPA2 handshakes for verifying passphrase. Example: -hC capture.pcap|
|-dE|--deauth-essid|Deauth all the BSSIDs having same ESSID from AP selection or the ESSID given by -e option.|
||--logging| Enable logging. Output will be saved to wifiphisher.log file.|
|-cM|--channel-monitor|Monitor if the target access point changes the channel.|
||--payload-path| Enable the payload path. Intended for use with scenarios that serve payloads.|
|-wP|--wps-pbc|Monitor if the button on a WPS-PBC Registrar side is pressed.|
|-wAI|--wpspbc-assoc-interface|The WLAN interface used for associating to the WPS AccessPoint.|
|-kb|--known-beacons|Perform the known beacons Wi-Fi automatic association technique.|


## Screenshots

<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/ss5.png" /><br /><i>Targeting an access point</i></p>
<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/ss2.png" /><br /><i>A successful attack</i></p>
<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/ss7.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/firmware-upgrade/">router configuration page</a></i></p>
<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/ss6.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/oauth-login/">OAuth Login Page</a></i></p>
<p align="center"><img src="https://wifiphisher.github.io/wifiphisher/ss4.png" /><br /><i>Fake <a href="https://wifiphisher.org/ps/wifi_connect/">web-based network manager</a></i></p>

## Help needed
If you are a Python developer or a web designer you can help us improve wifiphisher. Feel free to take a look at the <a href="https://github.com/wifiphisher/wifiphisher/issues">bug tracker</a> for some tasks to do.

If you don't know how to code, you can help us by <a href="https://github.com/wifiphisher/wifiphisher/issues">proposing improvements or reporting bugs</a>. Please have a look at the <a href="https://github.com/wifiphisher/wifiphisher/wiki/Bug-reporting-guidelines">Bug Reporting Guidelines</a> and the <a href="https://github.com/wifiphisher/wifiphisher/wiki/Frequently-Asked-Questions-%28FAQ%29">FAQ document</a> beforehand.  Note that the tool does not aim to be script-kiddie friendly. Make sure you do understand how the tool works before opening an issue.

## Credits
The script is based on an idea from <a
href="https://github.com/DanMcInerney">Dan McInerney</a> back in 2015.

A full list of contributors lies <a href="https://github.com/wifiphisher/wifiphisher/graphs/contributors">here</a>.

## License
Wifiphisher is licensed under the GPL license. See [LICENSE](LICENSE) for more information.

## Project Status
Wifiphisher's current version is **1.4**. You can download the latest release from <a href="https://github.com/wifiphisher/wifiphisher/releases/tag/v1.4">here</a>. Otherwise you can get the latest development version by cloning this repository.

## Disclaimer
* Usage of Wifiphisher for attacking infrastructures without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.

<b>Note</b>: Be aware of sites pretending to be related with the Wifiphisher Project. They may be delivering malware.

For Wifiphisher news, follow us on <a href="https://www.twitter.com/wifiphisher">Twitter</a> or like us on <a href="https://www.facebook.com/Wifiphisher-129914317622032/">Facebook</a>.
