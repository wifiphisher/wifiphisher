"""
All logic regarding extensions management
"""

import time
import importlib
import threading
import collections
import scapy.layers.dot11 as dot11
import scapy.arch.linux as linux
import wifiphisher.common.constants as constants


class ExtensionManager(object):
    """
    Extension Manager (EM) defines an API for modular
    architecture in Wifiphisher.

    All extensions that lie under "extensions" directory
    and are also defined in EXTENSIONS constant are loaded
    and leveraged by EM. Each extension can take advantage
    of the second wireless card (the first is used for the
    rogue AP), aka run in "Advanced mode".

    Each extension needs to be defined as a class that has
    the name of the filename in camelcase. For example,
    deauth.py would have a Deauth() class. Currently,
    extensions need to provide the following methods:

    * __init__(self, data): Basic initialization that
      received a dictionary with data from the main engine.

    * get_packet(self, pkt): Method to process individually
      each packet captured from the second card (monitor
      mode).

    * send_output(self): Method that returns in a list
      of strings the entry logs that need to be output.
    """

    def __init__(self):
        """
        Init the EM object.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        self._extensions_str = []
        self._extensions = []
        self._interface = None
        self._socket = None
        self._should_continue = True
        self._packets_to_send = {str(k): [] for k in range(1, 12)}
        self._packets_to_send["*"] = []
        self._channels_to_hop = []
        self._current_channel = "1"
        self.listen_thread = threading.Thread(target=self._listen)
        self.send_thread = threading.Thread(target=self._send)

    def _channel_hop(self):
        """
        Change the interface's channel every three seconds

        :param self: An AccessPointFinder object
        :type self: AccessPointFinder
        :return: None
        :rtype: None
        .. note: The channel range is between 1 to 13
        """

        # if the stop flag not set, change the channel
        while self._should_continue:
            for channel in self._channels_to_hop:
                self._current_channel = channel
                # added this check to reduce shutdown time
                if self._should_continue:
                    self._interface.set_channel(self._current_channel)
                    time.sleep(3)
                else:
                    break

    def set_interface(self, interface):
        """
        Sets interface for EM.

        :param interface: Interface name
        :type interface: String
        :return: None
        :rtype: None
        """

        self._interface = interface
        self._socket = linux.L2Socket(iface=self._interface.get_name())

    def set_extensions(self, extensions):
        """
        Sets extensions for EM.

        :param extensions: List of str extension names
        :type extensions: List
        :return: None
        :rtype: None
        """

        self._extensions_str = extensions

    def init_extensions(self, shared_data):
        """
        Init EM extensions. Should be run
        when all shared data has been gathered.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param shared_data: Dictionary object
        :type shared_data: Dictionary
        :return: None
        :rtype: None
        """

        # Convert shared_data from dict to named tuple
        shared_data = collections.namedtuple('GenericDict',
                                             shared_data.keys())(**shared_data)
        # Initialize all extensions with the shared data
        for extension in self._extensions_str:
            mod = importlib.import_module(
                constants.EXTENSIONS_LOADPATH + extension)
            ExtensionClass = getattr(mod, extension.title())
            obj = ExtensionClass(shared_data)
            self._extensions.append(obj)

    def start_extensions(self):
        """
        Starts the two main daemons of EM:

        1) Daemon that listens to every packet and
        forwards it to each extension for further processing.
        2) Daemon that receives special-crafted packets
        from extensions and broadcasts them in the air.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        # One daemon is listening for packets...
        self.listen_thread.start()
        # ...another daemon is sending packets
        self.send_thread.start()

    def on_exit(self):
        """
        Stops both daemons of EM on exit.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        self._should_continue = False
        if self.listen_thread.is_alive():
            self.listen_thread.join(5)
        if self.send_thread.is_alive():
            self.send_thread.join(5)

    def get_channels(self):
        """
        Gets the channels from each extension.
        Merges them to create a list of channels
        to hop.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        for extension in self._extensions:
            channels_interested = extension.send_channels()
            if channels_interested and len(channels_interested) > 0:
                self._channels_to_hop += channels_interested

    def get_output(self):
        """
        Gets the output of each extensions.
        Merges them in a list and returns it.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        output = []
        for extension in self._extensions:
            m_output = extension.send_output()
            if m_output and len(m_output) > 0:
                output += m_output
        return output

    def _process_packet(self, pkt):
        """
        Pass each captured packet to each module.
        Gets the packets to send.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param pkt: A Scapy packet object
        :type pkt: Scapy Packet
        :return: None
        :rtype: None
        """

        for extension in self._extensions:
            channel_nums, received_packets = extension.get_packet(pkt)
            if received_packets and len(received_packets) > 0:
                for c_num in channel_nums:
                    self._packets_to_send[c_num] += received_packets

    def _stopfilter(self, pkt):
        """
        A scapy filter to determine if we need to stop.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param self: A Scapy packet object
        :type self: Scapy Packet
        :return: True or False
        :rtype: Boolean
        """

        return not self._should_continue

    def _listen(self):
        """
        Listening thread. Listens for packets and forwards them
        to _process_packet.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        try:
            # continue to find clients until told otherwise
            while self._should_continue:
                dot11.sniff(
                    iface=self._interface.get_name(),
                    prn=self._process_packet,
                    count=1,
                    store=0,
                    stop_filter=self._stopfilter)
        # Don't display "Network is down" if shutting down
        except OSError:
            if not self._should_continue:
                pass

    def _send(self):
        """
        Sending thread. Continously broadcasting packets
        crafted by extensions.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        try:
            while self._should_continue:
                for pkt in self._packets_to_send[self._current_channel] + \
                        self._packets_to_send["*"]:
                    self._socket.send(pkt)
            time.sleep(1)
        # Don't display "Network is down" if shutting down
        except OSError:
            if not self._should_continue:
                pass
        finally:
            # Close socket
            self._socket.close()
