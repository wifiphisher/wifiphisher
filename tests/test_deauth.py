# pylint: skip-file
""" This module tests the deauth module in extensions """
import collections
import unittest
from collections import defaultdict

import mock
import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.extensions.deauth as deauth


class TestDeauth(unittest.TestCase):
    """ Tests Deauth class """

    def setUp(self):
        """ Set up the tests """

        essid = dot11.Dot11Elt(ID='SSID', info="")
        rates = dot11.Dot11Elt(ID='Rates', info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = dot11.Dot11Elt(ID='DSset', info='\x06')
        self.packet = dot11.RadioTap() / dot11.Dot11() / essid / rates / dsset

        custom_tuple = collections.namedtuple("test",
                                              ("target_ap_bssid target_ap_channel rogue_ap_mac args "
                                               "target_ap_essid is_freq_hop_allowed"))

        self.target_channel = "6"
        self.target_bssid = "BB:BB:BB:BB:BB:BB"
        self.rogue_mac = "CC:CC:CC:CC:CC:CC"
        self.target_essid = "Evil"
        self.args = mock.Mock()
        self.args.deauth_essid = False
        self.args.channel_monitor = False
        self.args.deauth_channels = []

        data0 = custom_tuple(self.target_bssid, self.target_channel, self.rogue_mac,
                             self.args, self.target_essid, True)
        data1 = custom_tuple(None, self.target_channel, self.rogue_mac,
                             self.args, self.target_essid, True)

        self.deauth_obj0 = deauth.Deauth(data0)
        self.deauth_obj1 = deauth.Deauth(data1)

        # test for --deauth-essid
        self.deauth_obj0._deauth_bssids = dict()
        self.deauth_obj1._deauth_bssids = dict()

    def test_craft_packet_normal_expected(self):
        """
        Test _craft_packet method when given all the normal arguments and
        expecting normal results
        """

        sender = "00:00:00:00:00:00"
        receiver = "11:11:11:11:11:11"
        bssid = "00:00:00:00:00:00"

        result = self.deauth_obj0._craft_packet(sender, receiver, bssid)
        message0 = "Failed to craft a packet for disassociation"
        message1 = "Failed to craft a packet for deauthentication"
        # check the disassociation packet
        self.assertEqual(result[0].addr1, receiver, message0)
        self.assertEqual(result[0].addr2, sender, message0)
        self.assertEqual(result[0].addr3, bssid, message0)

        # check the deauthentication packet
        self.assertEqual(result[1].addr1, receiver, message1)
        self.assertEqual(result[1].addr2, sender, message1)
        self.assertEqual(result[1].addr3, bssid, message1)

    def test_get_packet_broadcast(self):
        """
        Test get_packet method for crafting the broadcast frame
        """

        # setup the packet
        sender = "00:00:00:00:00:00"
        receiver = "11:11:11:11:11:11"
        essid = dot11.Dot11Elt(ID='SSID', info="")
        rates = dot11.Dot11Elt(ID='Rates', info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = dot11.Dot11Elt(ID='DSset', info='\x06')
        packet = dot11.RadioTap() / dot11.Dot11() / dot11.Dot11Beacon() / essid / rates / dsset

        packet.addr1 = receiver
        packet.addr2 = sender
        packet.addr3 = self.target_bssid
        packet.FCfield = 0x0

        # run the method
        pkts_to_send = self.deauth_obj0.get_packet(packet)
        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel: target channel should be one key of
        # the result
        self.assertEqual(self.target_channel in pkts_to_send, True,
                         message0)

        # check the packets
        # check the disassoction packet
        result = pkts_to_send[self.target_channel]
        self.assertEqual(result[0].subtype, 10, message1)
        self.assertEqual(result[0].addr1, constants.WIFI_BROADCAST, message1)
        self.assertEqual(result[0].addr2, self.target_bssid, message1)
        self.assertEqual(result[0].addr3, self.target_bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1].subtype, 12, message1)
        self.assertEqual(result[1].addr1, constants.WIFI_BROADCAST, message1)
        self.assertEqual(result[1].addr2, self.target_bssid, message1)
        self.assertEqual(result[1].addr3, self.target_bssid, message1)

    def test_get_packet_second_run_non_releavent_client_empty(self):
        """
        Test get_packet method for the second time when given a packet which
        is not related to the target access point and --essid is not used.
        The expected result are an channel list containing target channel and
        an empty packet list
        """

        # setup the packets
        sender0 = "00:00:00:00:00:00"
        receiver0 = "11:11:11:11:11:11"
        bssid0 = "22:22:22:22:22:22:22"

        sender1 = "33:33:33:33:33:33"
        receiver1 = "44:44:44:44:44:44"
        bssid1 = "55:55:55:55:55:55"

        self.packet.addr1 = receiver0
        self.packet.addr2 = sender0
        self.packet.addr3 = bssid0

        # run the method twice
        self.deauth_obj0.get_packet(self.packet)

        # change the values for the next run
        self.packet.addr1 = receiver1
        self.packet.addr2 = sender1
        self.packet.addr3 = bssid1

        result = self.deauth_obj0.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        # if the bssid is not in self._deauth_bssids, return empty channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        self.assertEqual(result[1], [], message1)

    def test_get_packet_second_run_our_ap_empty(self):
        """
        Test get_packet method for the second time when given a packet which
        is from our own rouge ap to the target access point and --essid is
        not used. The expected result are an channel list containing target
        channel and an empty packet list
        """

        # setup the packets
        sender0 = "00:00:00:00:00:00"
        receiver0 = "11:11:11:11:11:11"
        bssid0 = "22:22:22:22:22:22:22"

        sender1 = "33:33:33:33:33:33"
        receiver1 = "44:44:44:44:44:44"
        bssid1 = self.rogue_mac

        self.packet.addr1 = receiver0
        self.packet.addr2 = sender0
        self.packet.addr3 = bssid0

        # run the method twice
        self.deauth_obj0.get_packet(self.packet)

        # change the values for the next run
        self.packet.addr1 = receiver1
        self.packet.addr2 = sender1
        self.packet.addr3 = bssid1

        result = self.deauth_obj0.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        # return empty channel if the frame is invalid
        self.assertEqual(result[0], [], message0)

        # check the packets
        self.assertEqual(result[1], [], message1)

    def test_get_packet_multiple_clients_multiple_packets(self):
        """
        Test get_packet method when run multiple times with valid cleints.
        --essid is not used. The expected result are the channel of the
        target AP followed by the broadcast packet for the target AP and
        all the client packets
        """

        # setup the packet
        sender0 = self.target_bssid
        receiver0 = "11:11:11:11:11:11"
        bssid0 = self.target_bssid

        sender1 = "33:33:33:33:33:33"
        receiver1 = self.target_bssid
        bssid1 = self.target_bssid

        self.packet.addr1 = receiver0
        self.packet.addr2 = sender0
        self.packet.addr3 = bssid0

        # add target_bssid in the self._deauth_bssids
        self.deauth_obj0._deauth_bssids[self.target_bssid] = self.target_channel

        # run the method
        pkts_to_send0 = self.deauth_obj0.get_packet(self.packet)
        result0 = pkts_to_send0[self.target_channel]

        # change the values for the next run
        self.packet.addr1 = receiver1
        self.packet.addr2 = sender1
        self.packet.addr3 = bssid1

        # result1 will accumulate the result from result 0
        pkts_to_send1 = self.deauth_obj0.get_packet(self.packet)
        result1 = pkts_to_send1[self.target_channel]

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(self.target_channel in pkts_to_send0, True,
                         message0)

        # check the packets for the first client
        # check the disassociation packet
        self.assertEqual(result0[0].subtype, 10, message1)
        self.assertEqual(result0[0].addr1, self.target_bssid, message1)
        self.assertEqual(result0[0].addr2, receiver0, message1)
        self.assertEqual(result0[0].addr3, self.target_bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result0[1].subtype, 12, message1)
        self.assertEqual(result0[1].addr1, self.target_bssid, message1)
        self.assertEqual(result0[1].addr2, receiver0, message1)
        self.assertEqual(result0[1].addr3, self.target_bssid, message1)

        # check the disassociation packet
        self.assertEqual(result0[2].subtype, 10, message1)
        self.assertEqual(result0[2].addr1, receiver0, message1)
        self.assertEqual(result0[2].addr2, self.target_bssid, message1)
        self.assertEqual(result0[2].addr3, self.target_bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result0[3].subtype, 12, message1)
        self.assertEqual(result0[3].addr1, receiver0, message1)
        self.assertEqual(result0[3].addr2, self.target_bssid, message1)
        self.assertEqual(result0[3].addr3, self.target_bssid, message1)

        # check the packets for the second client
        # check the disassociation packet
        self.assertEqual(result1[4].subtype, 10, message1)
        self.assertEqual(result1[4].addr1, sender1, message1)
        self.assertEqual(result1[4].addr2, self.target_bssid, message1)
        self.assertEqual(result1[4].addr3, self.target_bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result1[5].subtype, 12, message1)
        self.assertEqual(result1[5].addr1, sender1, message1)
        self.assertEqual(result1[5].addr2, self.target_bssid, message1)
        self.assertEqual(result1[5].addr3, self.target_bssid, message1)

        # check the disassociation packet
        self.assertEqual(result1[6].subtype, 10, message1)
        self.assertEqual(result1[6].addr1, self.target_bssid, message1)
        self.assertEqual(result1[6].addr2, sender1, message1)
        self.assertEqual(result1[6].addr3, self.target_bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result1[7].subtype, 12, message1)
        self.assertEqual(result1[7].addr1, self.target_bssid, message1)
        self.assertEqual(result1[7].addr2, sender1, message1)
        self.assertEqual(result1[7].addr3, self.target_bssid, message1)

    def test_get_packet_essid_flag_client_client_packet(self):
        """
        Test get_packet method when --essid flag is given. A new
        client is given as input and the proper packets and the
        clients channel is expected
        """

        # setup the packet
        sender = "22:22:22:22:22:22"
        receiver = "11:11:11:11:11:11"
        bssid = receiver

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # add the bssid to the deauth_bssid set
        self.deauth_obj1._deauth_bssids[bssid] = self.target_channel

        # run the method
        pkts_to_send = self.deauth_obj1.get_packet(self.packet)
        result = pkts_to_send[self.target_channel]

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(self.target_channel in pkts_to_send, True, message0)

        # check the packets

        # check the disassociation packet
        self.assertEqual(result[0].subtype, 10, message1)
        self.assertEqual(result[0].addr1, sender, message1)
        self.assertEqual(result[0].addr2, receiver, message1)
        self.assertEqual(result[0].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1].subtype, 12, message1)
        self.assertEqual(result[1].addr1, sender, message1)
        self.assertEqual(result[1].addr2, receiver, message1)
        self.assertEqual(result[1].addr3, bssid, message1)

        # check the disassociation packet
        self.assertEqual(result[2].subtype, 10, message1)
        self.assertEqual(result[2].addr1, receiver, message1)
        self.assertEqual(result[2].addr2, sender, message1)
        self.assertEqual(result[2].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[3].subtype, 12, message1)
        self.assertEqual(result[3].addr1, receiver, message1)
        self.assertEqual(result[3].addr2, sender, message1)
        self.assertEqual(result[3].addr3, bssid, message1)

    def test_get_packet_essid_flag_our_own_ap_empty_list(self):
        """
        Test get_packet method when --essid flag is given. Our own
        client is given as input. An empty list for both channel and
        packets
        """

        # setup the packet
        sender = "00:00:00:00:00:00"
        receiver = self.rogue_mac
        bssid = self.rogue_mac

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # run the method
        result = self.deauth_obj1.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1], [], message1)

    @mock.patch("wifiphisher.extensions.deauth.ord")
    def test_get_packet_essid_flag_malformed0_channel_empty_list(self, mock_ord):
        """
        Test get_packet method when --essid flag is given. This is the
        case when a packet is malformed in the channel section. An empty
        list for both channel and packets. This test the TypeError case
        """

        mock_ord.side_effect = TypeError

        # setup the packet
        sender = "00:00:00:00:00:00"
        receiver = "11:11:11:11:11:11"
        bssid = "22:22:22:22:22:22:22"

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # run the method
        result = self.deauth_obj1.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1], [], message1)

    @mock.patch("wifiphisher.extensions.deauth.ord")
    def test_get_packet_essid_flag_malformed1_channel_empty_list(self, mock_ord):
        """
        Test get_packet method when --essid flag is given. This is the
        case when a packet is malformed in the channel section. An empty
        list for both channel and packets. This tests the IndexError case
        """

        mock_ord.side_effect = IndexError

        # setup the packet
        sender = "00:00:00:00:00:00"
        receiver = "11:11:11:11:11:11"
        bssid = "22:22:22:22:22:22:22"

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # run the method
        result = self.deauth_obj1.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1], [], message1)

    @mock.patch("wifiphisher.extensions.deauth.ord")
    def test_get_packet_essid_flag_malformed2_channel_empty_list(self, mock_ord):
        """
        Test get_packet method when --essid flag is given. This is the
        case when a packet is malformed in the channel section. In this case
        the channel reported is out of range and an empty list for both
        channel and packets
        """

        mock_ord.return_value = 200

        # setup the packet
        sender = "33:33:33:33:33:33"
        receiver = "11:11:11:11:11:11"
        bssid = "22:22:22:22:22:22:22"

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # run the method
        result = self.deauth_obj1.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1], [], message1)

    def test_add_client_invalid_sender_none(self):
        """
        Test _add_client when the given sender is in the non_client_address.
        The expected output is None
        """

        # setup the arguments
        sender = constants.WIFI_INVALID
        receiver = "11:11:11:11:11:11"
        bssid = receiver

        # run the method
        result = self.deauth_obj0._add_clients(sender, receiver, bssid)

        # check the result
        self.assertIsNone(result)

    def test_add_client_invalid_receiver_none(self):
        """
        Test _add_client when the given receiver is in the non_client_address.
        The expected output is None
        """

        # setup the arguments
        sender = "11:11:11:11:11:11"
        receiver = constants.WIFI_INVALID
        bssid = sender

        # run the method
        result = self.deauth_obj0._add_clients(sender, receiver, bssid)

        # check the result
        self.assertIsNone(result)

    def test_add_client_invalid_sender_receiver_none(self):
        """
        Test _add_client when the given sender and receiver are in the
        non_client_address. The expected output is None
        """

        # setup the arguments
        sender = constants.WIFI_INVALID
        receiver = constants.WIFI_INVALID
        bssid = "22:22:22:22:22:22:22"

        # run the method
        result = self.deauth_obj0._add_clients(sender, receiver, bssid)

        # check the result
        self.assertIsNone(result)

    def test_add_client_irrelevent_sender_receiver_none(self):
        """
        Test _add_client when neither sender nor receiver is the
        BSSID. The expected output is None
        """

        # setup the arguments
        sender = "11:11:11:11:11:11"
        receiver = "33:33:33:33:33:33"
        bssid = "22:22:22:22:22:22:22"

        # run the method
        result = self.deauth_obj0._add_clients(sender, receiver, bssid)

        # check the result
        self.assertIsNone(result)

    def test_add_client_receiver_is_bssid_packets(self):
        """
        Test _add_client when the given receiver is the bssid. The
        expected output is proper packets for both sender and receiver
        """

        # setup the packet
        sender = "22:22:22:22:22:22"
        receiver = "11:11:11:11:11:11"
        bssid = receiver

        # run the method
        result = self.deauth_obj1._add_clients(sender, receiver, bssid)

        message0 = "Failed to return the correct client"
        message1 = "Failed to return an correct packets"

        # check the client
        self.assertEqual(result[0], sender, message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1][0].subtype, 10, message1)
        self.assertEqual(result[1][0].addr1, sender, message1)
        self.assertEqual(result[1][0].addr2, receiver, message1)
        self.assertEqual(result[1][0].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1][1].subtype, 12, message1)
        self.assertEqual(result[1][1].addr1, sender, message1)
        self.assertEqual(result[1][1].addr2, receiver, message1)
        self.assertEqual(result[1][1].addr3, bssid, message1)

        # check the disassociation packet
        self.assertEqual(result[1][2].subtype, 10, message1)
        self.assertEqual(result[1][2].addr1, receiver, message1)
        self.assertEqual(result[1][2].addr2, sender, message1)
        self.assertEqual(result[1][2].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1][3].subtype, 12, message1)
        self.assertEqual(result[1][3].addr1, receiver, message1)
        self.assertEqual(result[1][3].addr2, sender, message1)
        self.assertEqual(result[1][3].addr3, bssid, message1)

    def test_add_client_sender_is_bssid_packets(self):
        """
        Test _add_client when the given sender is the bssid. The
        expected output is proper packets for both sender and receiver
        """

        # setup the packet
        sender = "22:22:22:22:22:22"
        receiver = "11:11:11:11:11:11"
        bssid = sender

        # run the method
        result = self.deauth_obj1._add_clients(sender, receiver, bssid)

        message0 = "Failed to return the correct client"
        message1 = "Failed to return an correct packets"

        # check the client
        self.assertEqual(result[0], receiver, message0)

        # check the packets
        # check the disassociation packet
        self.assertEqual(result[1][0].subtype, 10, message1)
        self.assertEqual(result[1][0].addr1, sender, message1)
        self.assertEqual(result[1][0].addr2, receiver, message1)
        self.assertEqual(result[1][0].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1][1].subtype, 12, message1)
        self.assertEqual(result[1][1].addr1, sender, message1)
        self.assertEqual(result[1][1].addr2, receiver, message1)
        self.assertEqual(result[1][1].addr3, bssid, message1)

        # check the disassociation packet
        self.assertEqual(result[1][2].subtype, 10, message1)
        self.assertEqual(result[1][2].addr1, receiver, message1)
        self.assertEqual(result[1][2].addr2, sender, message1)
        self.assertEqual(result[1][2].addr3, bssid, message1)

        # check the deauthentication packet
        self.assertEqual(result[1][3].subtype, 12, message1)
        self.assertEqual(result[1][3].addr1, receiver, message1)
        self.assertEqual(result[1][3].addr2, sender, message1)
        self.assertEqual(result[1][3].addr3, bssid, message1)

    def test_send_output_no_client_proper(self):
        """
        Test send_output method when no client has been detected.
        The expected result is an empty message list
        """

        message = "Failed to send the proper output"

        self.assertEqual(self.deauth_obj1.send_output(), [], message)

    def test_send_output_single_client_proper(self):
        """
        Test send_output method when a client has been already
        detected. The expected result is the proper output
        containing that client
        """

        # setup the packet
        sender = "44:44:44:44:44:44"
        receiver = "55:55:55:55:55:55"
        bssid = receiver

        self.packet.addr1 = receiver
        self.packet.addr2 = sender
        self.packet.addr3 = bssid

        # run the method
        self.deauth_obj1._deauth_bssids[bssid] = self.target_channel
        self.deauth_obj1.get_packet(self.packet)
        actual = self.deauth_obj1.send_output()
        expected = "DEAUTH/DISAS - {}".format(sender)

        message = "Failed to send the proper output"

        self.assertEqual(expected, actual[0], message)

    def test_send_output_multiple_client_proper(self):
        """
        Test send_output method when multiple client has been already
        detected. The expected result is the proper output
        containing that clients
        """

        # setup the packet
        sender0 = "22:22:22:22:22:22"
        receiver0 = "11:11:11:11:11:11"
        bssid0 = receiver0

        sender1 = "33:33:33:33:33:33"
        receiver1 = "44:44:44:44:44:44"
        bssid1 = sender1

        self.packet.addr1 = receiver0
        self.packet.addr2 = sender0
        self.packet.addr3 = bssid0

        # run the method
        self.deauth_obj1._deauth_bssids[bssid0] = self.target_channel
        self.deauth_obj1.get_packet(self.packet)

        # change the packet details
        self.packet.addr1 = receiver1
        self.packet.addr2 = sender1
        self.packet.addr3 = bssid1

        # run the method again
        self.deauth_obj1._deauth_bssids[bssid1] = self.target_channel
        self.deauth_obj1.get_packet(self.packet)

        actual = self.deauth_obj1.send_output()
        expected0 = "DEAUTH/DISAS - {}".format(sender0)
        expected1 = "DEAUTH/DISAS - {}".format(receiver1)

        self.assertIn(expected0, actual)
        self.assertIn(expected1, actual)

    def test_send_channels_non_frenzy_target_channel(self):
        """
        Test send_channels method when --essid is not given. The
        expected result is the target AP's channel
        """

        actual = self.deauth_obj0.send_channels()

        message = "Failed to send target AP's channel"

        expected = [self.target_channel]

        self.assertEqual(expected, actual, message)

    def test_send_channels_frenzy_all_channels(self):
        """
        Test send_channels method when --essid is given. The expected
        result is all channels
        """

        actual = self.deauth_obj1.send_channels()

        message = "Failed to send all the channels"

        expected = [str(ch) for ch in range(1, 14)]

        self.assertEqual(expected, actual, message)

    def test_extract_bssid_to_ds_0_from_ds_1_addr2(self):
        """
        Test _extract_bssid when to_ds is 1 and from_ds is 0.
        The case should return packet.addr2
        """
        # bit0 is to_ds and bit1 is from_ds
        self.packet.FCfield = 2
        self.packet.addr1 = "11:11:11:11:11:11"
        self.packet.addr2 = "22:22:22:22:22:22"
        self.packet.addr3 = "33:33:33:33:33:33"

        message = "Fail to get correct BSSID as address 2"
        actual = self.deauth_obj0._extract_bssid(self.packet)
        expected = self.packet.addr2

        self.assertEqual(expected, actual, message)

    def test_extract_bssid_to_ds_1_from_ds_0_addr1(self):
        """
        Test _extract_bssid when to_ds is 1 and from_ds is 0.
        The case should return packet.addr2
        """
        # bit0 is to_ds and bit1 is from_ds
        self.packet.FCfield = 1
        self.packet.addr1 = "11:11:11:11:11:11"
        self.packet.addr2 = "22:22:22:22:22:22"
        self.packet.addr3 = "33:33:33:33:33:33"

        message = "Fail to get correct BSSID as address 1"
        actual = self.deauth_obj0._extract_bssid(self.packet)
        expected = self.packet.addr1

        self.assertEqual(expected, actual, message)

    def test_extract_bssid_to_ds_0_from_ds_0_addr3(self):
        """
        Test _extract_bssid when to_ds is 0 and from_ds is 0.
        The case should return packet.addr3
        """
        # bit0 is to_ds and bit1 is from_ds
        self.packet.FCfield = 0
        self.packet.addr1 = "11:11:11:11:11:11"
        self.packet.addr2 = "22:22:22:22:22:22"
        self.packet.addr3 = "33:33:33:33:33:33"

        message = "Fail to get correct BSSID as address 3"
        actual = self.deauth_obj0._extract_bssid(self.packet)
        expected = self.packet.addr3

        self.assertEqual(expected, actual, message)

    def test_get_packet_to_ds_1_from_ds_1_empty(self):
        """
        Drop the WDS frame in get_packet
        """

        self.packet.FCfield = 3
        result = self.deauth_obj0.get_packet(self.packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        self.assertEqual(result[1], [], message1)

    def test_get_packet_address_malform_empty(self):
        """
        Drop the frame if the address is malformed
        """

        packet = mock.Mock(spec=[])
        result = self.deauth_obj0.get_packet(packet)

        message0 = "Failed to return an correct channel"
        message1 = "Failed to return an correct packets"

        # check channel
        self.assertEqual(result[0], [], message0)

        # check the packets
        self.assertEqual(result[1], [], message1)

    def test_is_target_target_ap_bssid_true(self):
        """
        Get the target attacking bssid for the speficic ESSID
        when --essid is not used
        """
        essid = dot11.Dot11Elt(ID='SSID', info="Evil")
        packet = dot11.RadioTap() / dot11.Dot11() / dot11.Dot11Beacon() / essid
        packet.addr3 = "99:99:99:99:99:99"
        self.deauth_obj0._data.args.deauth_essid = "Evil"
        result = self.deauth_obj0._is_target(packet)

        expected = True
        message = "Fail to check the attacking essid: " + self.target_essid
        self.assertEqual(result, expected, message)

    def test_is_target_essid_non_decodable_error(self):
        """
        Assign essid to a constant when it is utf-8 non-decodable
        """
        essid = dot11.Dot11Elt(ID='SSID', info='\x99\x87\x33')
        packet = dot11.RadioTap() / dot11.Dot11() / dot11.Dot11Beacon() / essid
        packet.addr3 = "99:99:99:99:99:99"
        result = self.deauth_obj0._is_target(packet)
        expected = False
        message = 'Fail to raise the UnicodeDecodeError for non-printable essid'
        self.assertEqual(result, expected, message)

    def test_channel_deauth(self):
        """
        Test that we are deauthing on the right channels each time.
        """

        # In obj0 we are targetting a specific AP 
        # Default behavior (e.g. through AP selection phase)
        result = self.deauth_obj0.send_channels()
        expected = [str(self.deauth_obj0._data.target_ap_channel)]
        message = "Fail to receive right channels"
        self.assertEqual(result, expected, message)

        # In obj1 we set --deauth-channels 1 2 3 4
        self.deauth_obj1._data.args.deauth_channels = [1, 2, 3, 4]
        result = self.deauth_obj1.send_channels()
        expected = ['1', '2', '3', '4']
        message = "Fail to receive right channels"
        self.assertEqual(result, expected, message)
