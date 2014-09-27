<p align="center"><img src="https://sophron.github.io/wifiphisher/wifiphisher.png" /></p>

## About
Wifiphisher is a security tool that mounts fast automated phishing attacks against WPA networks in order to obtain the secret passphrase. It is a social engineering attack that unlike other methods it does not include any brute forcing. It is an easy way for obtaining WPA credentials.

From the victim's perspective, the attack makes use in three phases:

1. **Victim is being deauthenticated from her access point**. Wifiphisher continuously jams all of the target access point's wifi devices within range by sending deauth packets to the client from the access point, to the access point from the client, and to the broadcast address as well. 
2. **Victim joins a rogue access point**. Wifiphisher sniffs the area and copies the target access point's settings. It then creates a rogue wireless access point that is modeled on the target. It also sets up a NAT/DHCP server and forwards the right ports. Consequently, because of the jamming, clients will start connecting to the rogue access point. After this phase, the victim is MiTMed.
3. **Victim is being served a realistic router config-looking page**. wifiphisher employs a minimal web server that responds to HTTP & HTTPS requests. As soon as the victim requests a page from the Internet, wifiphisher will respond with a realistic fake page that asks for WPA password confirmation due to a router firmware upgrade.

Wifiphisher works on Kali Linux and is licensed under the MIT license.

## Usage

## Making the attacks more successful


## Requirements
* Kali Linux.
* Two network interfaces, one wireless.
* A wireless card capable of injection.

## Credits
The idea belongs to <a href="https://github.com/DanMcInerney">Dan McInerney</a> who also authored two essential modules of this script, <a href="https://github.com/DanMcInerney/wifijammer">wifijammer</a> and <a href="https://github.com/DanMcInerney/fakeAP">fakeAP</a>.

## License
Wifiphisher is licensed under the MIT license. See [LICENSE](LICENSE) for more information.
