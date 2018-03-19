Frequently Asked Questions
==========================

Can we somehow bypass the SSL warning displayed by the browsers?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, Wifiphisher will try to imitate the behavior of a public
hotspot. Redirection to a captive portal served over HTTPS with a self-signed
certificate is what a user will typically experience when connecting to a captive portal.

If, however, one wants to use Wifiphisher to obtain a man-in-the-middle position
and effectively bypass HSTS / HTTPS, it is recommended to use Wifiphisher in
conjuction with other security tools.  For example, a user can run Wifiphisher
and provide the victims with Internet (using the -iI option) and at the same
time leverage the Evilginx project using a valid domain and a valid SSL
certificate.


Can we grab the Pre-Shared Key (PSK) of the target network during the association process of a victim station with the rogue Access Point?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No, it is not possible. In WPA/WPA2 protocols the password is never transmitted
in the air. The data is encrypted with the password and only the password on the
other side (AP) can be used to decrypt it.

Why some victim users do not automatically connect to the rogue Access Point?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A successful automatic association attack relies on many different factors including:

* Victim's Network Manager. Different Operating Systems support different
  wireless features. For example, an Android device will, by default, connect
  automatically to previously connected open networks making it susceptible to
  the Known Beacons Wi-Fi automatic association attack. At the same time iOS
  devices are configured to arbitrarily trasmit probe request frames for
  previously connected networks making them vulnerable to the KARMA attack.  

* Victim's Preferred Network List. KARMA and Known Beacons attacks heavily rely
  on the victim's Preferred Network List. The number of open "trusted" networks
  in the victim's PNL will significantly raise the chances for a succesfull
  attack. On the other hand, if the Preferred Network List is empty, these
  attacks are doomed to fail.

Why does deauthentication is not always working?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The two most common reasons are:

* You are physically too far away from the victim clients. You need enough
  transmit power for the packets to be heard by the clients.

* The wireless card used for the deauthentication attack operates in a
  different mode than the victim's card, hence the client is not able to
  receive the frames.
