<p align="center"><img src="https://sophron.github.io/wifiphisher/wifiphisher.png" /></p>

## About
Wifiphisher is a security tool that mounts automated phishing attacks against WiFi networks in order to obtain secret passphrases or other credentials. It is a social engineering attack that unlike other methods it does not include any brute forcing. It is an easy way for obtaining credentials from captive portals and third party login pages or WPA/WPA2 secret passphrases.

Wifiphisher works on Kali Linux and is licensed under the GPL license.

## How it works
After achieving a man-in-the-middle position using the Evil Twin attack, wifiphisher redirects all HTTP requests to an attacker-controlled look-alike web site.

From the victim's perspective, the attack makes use in three phases:

1. **Victim is being deauthenticated from her access point**. Wifiphisher continuously jams all of the target access point's wifi devices within range by forging “Deauthenticate” or “Disassociate” packets to disrupt existing associations.
2. **Victim joins a rogue access point**. Wifiphisher sniffs the area and copies the target access point's settings. It then creates a rogue wireless access point that is modeled by the target. It also sets up a NAT/DHCP server and forwards the right ports. Consequently, because of the jamming, clients will start connecting to the rogue access point. After this phase, the victim is MiTMed.
3. **Victim is being served a realistic router config-looking page**. Wifiphisher employs a minimal web server that responds to HTTP & HTTPS requests. As soon as the victim requests a page from the Internet, wifiphisher will respond with a realistic fake page that asks for credentials. The tool supports community-built templates for different phishing scenarios, such as:
  * Router configuration pages that ask for the WPA/WPA2 passphrase due to a router firmware upgrade.
  * 3rd party login pages (for example, login pages similar to those of popular social networking or e-mail access sites and products)
  * Captive portals, like the ones that are being used by hotels and airports.

<p align="center"><img width="70%" src="https://sophron.github.io/wifiphisher/diagram.jpg" /><br /><i>Performing MiTM attack</i></p>

## Usage

Run the tool by hitting `python bin/wifiphisher`. 

Following are some common options along with their descriptions:

| Short form | Long form | Explanation |
| :----------: | :---------: | :-----------: |
| -m | maximum | Choose the maximum number of clients to deauth. List of clients will be emptied and repopulated after hitting the limit. Example: -m 5 |
| -n | noupdate | Do not clear the deauth list when the maximum (-m) number of client/AP combos is reached. Must be used in conjunction with -m. Example: -m 10 -n |
| -t | timeinterval | Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001 |
| -p | packets | Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2 |
| -d | directedonly | Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs |
| -a | accesspoint | Enter the MAC address of a specific access point to target |
| -jI | jamminginterface | Choose the interface for jamming. By default script will find the most powerful interface and starts monitor mode on it. |
| -aI | apinterface | Choose the interface for the fake AP.  By default script will find the second most powerful interface and starts monitor mode on it. |

## Screenshots

<p align="center"><img src="https://sophron.github.io/wifiphisher/ss1.png" /><br /><i>Targeting an access point</i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss2.png" /><br /><i>A successful attack</i></p>
<p align="center"><img src="https://sophron.github.io/wifiphisher/ss3.png" /><br /><i>Fake router configuration page</i></p>


## Requirements
* Kali Linux.
* Two wireless network adapters; one capable of injection.

## Help needed
If you are a Python developer or a web designer you can help us improve wifiphisher. Feel free to take a look at the <a href="https://github.com/sophron/wifiphisher/issues">bug tracker</a> for some tasks to do.

If you don't know how to code, you can help us by <a href="https://github.com/sophron/wifiphisher/issues">proposing improvements or reporting bugs</a>. Please have a look at the <a href="https://github.com/sophron/wifiphisher/wiki/Bug-reporting-guidelines">Bug Reporting Guidelines</a> and the <a href="https://github.com/sophron/wifiphisher/wiki/Frequently-Asked-Questions-%28FAQ%29">FAQ document</a> beforehand.  Note that the tool does not aim to be script-kiddie friendly. Make sure you do understand how the tool works before opening an issue.

## Credits
The script is based on an idea from <a
href="https://github.com/DanMcInerney">Dan McInerney</a>. The parts for the
jamming and selecting an AP have also been taken from his scripts <a
href="https://github.com/DanMcInerney/wifijammer">wifijammer</a> and <a
href="https://github.com/DanMcInerney/fakeAP">fakeAP</a>.

A full list of contributors lies <a href="https://github.com/sophron/wifiphisher/graphs/contributors">here</a>.

## License
Wifiphisher is licensed under the GPL license. See [LICENSE](LICENSE) for more information.

## Project Status & Download
Wifiphisher's current version is **1.1**. You can download the latest release from <a href="https://github.com/sophron/wifiphisher/releases/tag/v1.1">here</a>. Otherwise you can get the latest development version by cloning this repository. 

## Other resources
* Official wiki: https://github.com/sophron/wifiphisher/wiki
* “Introducing wifiphisher“ talk at BSidesLondon: https://www.youtube.com/watch?v=pRtxFWJTS4k
* HowTo video by JackkTutorials: https://www.youtube.com/watch?v=tCwclyurB8I
* "Get Anyone's Wi-Fi Password Without Cracking Using Wifiphisher" by Null Byte: http://null-byte.wonderhowto.com/how-to/hack-wi-fi-get-anyones-wi-fi-password-without-cracking-using-wifiphisher-0165154/

<b>Note</b>: This is the only official page for wifiphisher. Other sites may be delivering malware.

[![alt text][1.1]][1]
[1.1]: http://i.imgur.com/tXSoThF.png (Follow me)
[1]: http://www.twitter.com/_sophron
