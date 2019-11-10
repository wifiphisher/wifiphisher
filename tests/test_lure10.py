""" This module tests the interface module """

import collections
import io
import unittest
from collections import defaultdict

import mock
import wifiphisher.common.constants as constants
import wifiphisher.extensions.lure10 as lure10


class TestLure10(unittest.TestCase):
    """ Tests Lure10 class """

    def setUp(self):
        """ Set up the variables """

        self.pkt = None
        self.channel = 6

        custom_tuple = collections.namedtuple("test", "args target_ap_channel")
        custom_tuple1 = collections.namedtuple("test1", "lure10_exploit")
        data0 = custom_tuple1("test")
        data1 = custom_tuple(data0, self.channel)
        data2 = custom_tuple1(None)
        data3 = custom_tuple(data2, self.channel)

        self._object0 = lure10.Lure10(data1)
        self._object1 = lure10.Lure10(data3)

    def test_get_packet_first_run_no_argument_empty(self):
        """
        Test get_packet method on the first run when the
        lure10_exploit argument is not given and the expected
        result is defaultdict{"*": []}
        """

        actual = self._object1.get_packet(self.pkt)

        expected = defaultdict(list)
        expected["*"] = []

        self.assertEqual(actual, expected)

    def test_get_packet_secon_run_no_argument_emtpy(self):
        """
        Test get_packet method on the second run when the
        lure10_exploit argument is not given and the expected
        result is defaultdict{"*": []}
        """

        self._object1.get_packet(self.pkt)
        actual = self._object1.get_packet(self.pkt)

        expected = defaultdict(list)
        expected["*"] = []

        self.assertEqual(actual, expected)

    def test_get_packet_first_run_argument_packet(self):
        """
        Test get_packet method on the first run when the lure10_exploit argument
        is given and the expected result is the packets
        """

        bssid0 = "11:11:11:11:11:11"
        bssid1 = "22:22:22:22:22:22"

        content = io.StringIO(u"{} one\n{} two".format(bssid0, bssid1))
        with mock.patch("wifiphisher.extensions.lure10.open", return_value=content, create=True):
            pkts_to_send = self._object0.get_packet(self.pkt)

        result = pkts_to_send["*"]

        # result is the frame list
        self.assertEqual(result[0].subtype, 8)
        self.assertEqual(result[0].addr1, constants.WIFI_BROADCAST)
        self.assertEqual(result[0].addr2, bssid0)
        self.assertEqual(result[0].addr3, bssid0)

        self.assertEqual(result[1].subtype, 8)
        self.assertEqual(result[1].addr1, constants.WIFI_BROADCAST)
        self.assertEqual(result[1].addr2, bssid1)
        self.assertEqual(result[1].addr3, bssid1)

    def test_get_packet_second_run_argument_empty(self):
        """
        Test get_packet method on the second run when the lure10_exploit argument
        is given and the expected result is no packets
        """

        bssid0 = "11:11:11:11:11:11"
        bssid1 = "22:22:22:22:22:22"

        content = io.StringIO(u"{} one\n{} two".format(bssid0, bssid1))
        with mock.patch("wifiphisher.extensions.lure10.open", return_value=content, create=True):
            first_run_frames = self._object0.get_packet(self.pkt)

        actual = self._object0.get_packet(self.pkt)
        # the frames collected from second run should be same as
        # in the first run
        expected = first_run_frames

        self.assertEqual(actual, expected)

    def test_send_output_before_first_run_with_argument_empty(self):
        """
        Test send_output method before the first run of get_packet and the
        lure10_exploit argument is given. The expected output is an empty
        list
        """

        result = self._object0.send_output()

        self.assertEqual([], result)

    def test_send_output_after_first_run_with_argument_proper(self):
        """
        Test send_output method after the first run of get_packet and the
        lure10_exploit argument is given. The expected output is the proper
        message
        """

        bssid0 = "11:11:11:11:11:11"
        bssid1 = "22:22:22:22:22:22"

        content = io.StringIO(u"{} one\n{} two".format(bssid0, bssid1))
        with mock.patch("wifiphisher.extensions.lure10.open", return_value=content, create=True):
            self._object0.get_packet(self.pkt)

        result = self._object0.send_output()
        expected = ["Lure10 - Spoofing location services"]
        self.assertEqual(result, expected)

    def test_send_output_before_first_run_no_argument_empty(self):
        """
        Test send_output method before the first run of get_packet and the
        lure10_exploit argument is not given. The expected output is an empty
        list
        """

        result = self._object1.send_output()

        self.assertEqual([], result)

    def test_send_output_after_first_run_no_argument_empty(self):
        """
        Test send_output method after the first run of get_packet and the
        lure10_exploit argument is not given. The expected output is an empty
        list
        """

        bssid0 = "11:11:11:11:11:11"
        bssid1 = "22:22:22:22:22:22"

        content = io.StringIO(u"{} one\n{} two".format(bssid0, bssid1))
        with mock.patch("wifiphisher.extensions.lure10.open", return_value=content, create=True):
            self._object1.get_packet(self.pkt)

        self._object1.send_output()
        result = self._object1.send_output()

        self.assertEqual([], result)

    def test_send_channels_proper(self):
        """
        Test send_channels method to make sure that the expected result of the
        target channel is returned
        """

        result = self._object0.send_channels()

        self.assertEqual(result, [self.channel])
