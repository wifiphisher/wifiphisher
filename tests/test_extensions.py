"""
Unit tests for Extension Manager
"""

import os
import shutil
import sys
import unittest

import mock
import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.common.extensions as extensions
import wifiphisher.common.interfaces as interfaces

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(os.path.join(dir_of_executable, '..'))
sys.path.insert(0, path_to_project_root)
os.chdir(path_to_project_root)


CONTENTS_EXTENSION_1 = """
import os
import importlib
from collections import defaultdict
import struct

class Extension1(object):

    def __init__(self, shared_data):
        self.data = shared_data
        self._packets_to_send = defaultdict(list)

    def get_packet(self, pkt):
        self._packets_to_send["1"] = [self.data.one]
        return self._packets_to_send

    def send_output(self):
        return ["one", "two"]
"""

CONTENTS_EXTENSION_2 = """
import os
import importlib
from collections import defaultdict
import struct

class Extension2(object):

    def __init__(self, shared_data):
        self._packets_to_send = defaultdict(list)

    def get_packet(self, pkt):
        self._packets_to_send["1"] = [2, 3, 4]
        return self._packets_to_send

    def send_output(self):
        return ["three", "four", "five"]
"""
# add extension for testing the channel ["*"]
CONTENTS_EXTENSION_3 = """
import os
import importlib
from collections import defaultdict
import struct

class Extension3(object):

    def __init__(self, shared_data):
        self._packets_to_send = defaultdict(list)

    def get_packet(self, pkt):
        self._packets_to_send["*"] = [5, 6, 7, 8]
        return self._packets_to_send

    def send_output(self):
        return []
"""


class TestExtensionManager(unittest.TestCase):

    def setUp(self):
        os.mkdir("tests/extensions")
        with open("tests/extensions/__init__.py", "a") as f:
            os.utime("tests/extensions/__init__.py", None)
            f.close()
        with open("tests/extensions/extension1.py", "w") as f:
            f.write(CONTENTS_EXTENSION_1)
            f.close()
        with open("tests/extensions/extension2.py", "w") as f:
            f.write(CONTENTS_EXTENSION_2)
            f.close()
        with open("tests/extensions/extension3.py", "w") as f:
            f.write(CONTENTS_EXTENSION_3)
            f.close()

    @mock.patch("wifiphisher.common.constants.DEFAULT_EXTENSIONS",
                ["extension1"])
    @mock.patch(
        "wifiphisher.common.constants.EXTENSIONS_LOADPATH",
        "tests.extensions.")
    def test_single_extension(self):
        # We need a NM to init EM
        nm = interfaces.NetworkManager()
        # Init an EM and pass some shared data
        em = extensions.ExtensionManager(nm)
        em.set_extensions(constants.DEFAULT_EXTENSIONS)
        shared_data = {"one": 1, "two": 2, "is_freq_hop_allowed": True}
        em.init_extensions(shared_data)
        # A deauth packet appears in the air
        packet = (
            dot11.RadioTap() /
            dot11.Dot11(
                type=0,
                subtype=12,
                addr1="00:00:00:00:00:00",
                addr2="00:00:00:00:00:00",
                addr3="00:00:00:00:00:00") /
            dot11.Dot11Deauth())
        em._process_packet(packet)
        # The extension1.py sent packet "1" and returned output
        # "one", "two". Validate with get_packet(), send_output()
        assert em._packets_to_send["1"] == [1]
        assert em._packets_to_send["2"] == []
        assert em.get_output() == ["one", "two"]

    @mock.patch(
        "wifiphisher.common.constants.DEFAULT_EXTENSIONS", [
            "extension1", "extension2", "extension3"])
    @mock.patch(
        "wifiphisher.common.constants.EXTENSIONS_LOADPATH",
        "tests.extensions.")
    def test_multiple_extensions(self):
        # We need a NM to init EM
        nm = interfaces.NetworkManager()
        # Init an EM and pass some shared data
        em = extensions.ExtensionManager(nm)
        em.set_extensions(constants.DEFAULT_EXTENSIONS)
        shared_data = {"one": 1, "two": 2, "is_freq_hop_allowed": True}
        em.init_extensions(shared_data)
        # A deauth packet appears in the air
        packet = (
            dot11.RadioTap() /
            dot11.Dot11(
                type=0,
                subtype=12,
                addr1="00:00:00:00:00:00",
                addr2="00:00:00:00:00:00",
                addr3="00:00:00:00:00:00") /
            dot11.Dot11Deauth())
        em._process_packet(packet)
        # Packets to send have been merged from the two extensions
        # Validate with get_packet()
        assert em._packets_to_send["1"] == [1, 2, 3, 4]
        assert em._packets_to_send["*"] == [5, 6, 7, 8]
        # Output has also been merged in one list.
        # Validate with send_output()
        assert em.get_output() == ["one", "two", "three", "four", "five"]

    def tearDown(self):
        shutil.rmtree("tests/extensions")


if __name__ == "__main__":
    unittest.main()
