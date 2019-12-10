"""
All logic regarding extensions management
"""

import collections
import importlib
import logging
import threading
import time
from collections import defaultdict

import scapy.arch.linux as linux
import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants
import wifiphisher.common.globals as universal
import wifiphisher.extensions.deauth as deauth_extension

logger = logging.getLogger(__name__)
is_deauth_cont = True


def register_backend_funcs(func):
    """
    Register the specific function in extension as backend methods
    :param func: The instance function needed to register as backend
    method
    :type func: instancemethod
    :return: None
    """

    func.is_backendmethod = True
    return func


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
      of strings the entry logs that we need to output.

    * on_exit(self): Method that frees all the used resources

    * each extension can define the backend method as follows:
      ex:

      @extensions.register_backend_funcs
      def psk_verify(self, *list_data):
          return list_data
    """

    def __init__(self, network_manager):
        """
        Init the EM object.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        self._nm = network_manager
        self._extensions_str = []
        self._extensions = []
        self._interface = None
        self._socket = None
        self._should_continue = True
        self._packets_to_send = defaultdict(list)
        self._channels_to_hop = []
        self._current_channel = "1"
        self._listen_thread = threading.Thread(target=self._listen)
        self._send_thread = threading.Thread(target=self._send)
        self._channelhop_thread = threading.Thread(target=self._channel_hop)
        self._shared_data = None

    def get_ui_funcs(self):
        """
        Returns a list of all the uimethods.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: List Object
        :rtype: List
        """

        ui_funcs = []
        # loop each extension object
        for extension in self._extensions:
            # loop all the attribute for the extension object
            for attr in dir(extension):
                if callable(getattr(extension, attr)):
                    method = getattr(extension, attr)
                    if hasattr(method, "is_uimethod"):
                        ui_funcs.append(method)
        return ui_funcs

    def get_backend_funcs(self):
        """
        Returns a list of all the backend methods

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: dict object
        :rtype: dict
        """

        backend_funcs = {}
        for extension in self._extensions:
            for attrname in dir(extension):
                method = getattr(extension, attrname)
                if hasattr(method, 'is_backendmethod'):
                    # store the method name to extension map
                    backend_funcs[method.__name__] = extension

        return backend_funcs

    def _channel_hop(self):
        """
        Change the interface's channel every three seconds

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        .. note: The channel range is between 1 to 13
        """

        # set the current channel to the ap channel
        self._nm.set_interface_channel(self._interface,
                                       int(self._shared_data.target_ap_channel))

        # if the stop flag not set, change the channel
        while self._should_continue:
            for channel in self._channels_to_hop:
                if self._current_channel != channel:
                    self._current_channel = channel
                    # added this check to reduce shutdown time
                    if self._should_continue:
                        try:
                            self._socket.close()
                            self._nm.set_interface_channel(
                                self._interface, int(self._current_channel))
                            self._socket = linux.L2Socket(
                                iface=self._interface)
                            # extends the channel hopping time to sniff
                            # more frames
                            time.sleep(3)
                        except BaseException:
                            continue
                    else:
                        break

    def set_interface(self, interface):
        """
        Sets interface for EM.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param interface: Interface name
        :type interface: String
        :return: None
        :rtype: None
        """

        self._interface = interface
        self._socket = linux.L2Socket(iface=self._interface)

    def set_extensions(self, extensions):
        """
        Sets extensions for EM.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
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
                                             list(shared_data.keys()))(**shared_data)
        self._shared_data = shared_data

        # Initialize all extensions with the shared data
        for extension in self._extensions_str:
            mod = importlib.import_module(constants.EXTENSIONS_LOADPATH +
                                          extension)
            extension_class = getattr(mod, extension.title())
            obj = extension_class(shared_data)
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
        self._listen_thread.start()
        # ...another daemon is sending packets
        self._send_thread.start()
        # daemon for channel hopping
        self.get_channels()
        if self._shared_data.is_freq_hop_allowed:
            self._channelhop_thread.start()
        else:
            self._current_channel = self._shared_data.target_ap_channel

    def on_exit(self):
        """
        Stops both daemons of EM on exit.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        self._should_continue = False
        if self._listen_thread.is_alive():
            self._listen_thread.join(3)
        if self._send_thread.is_alive():
            self._send_thread.join(3)
        if (self._shared_data is not None
                and self._shared_data.is_freq_hop_allowed
                and self._channelhop_thread.is_alive()):
            self._channelhop_thread.join(3)
        # Close socket if it's open
        try:
            self._socket.close()
        except AttributeError:
            pass
        # Clean resources used by extension modules
        for extension in self._extensions:
            extension.on_exit()

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
            number_of_channels = len(channels_interested)
            if channels_interested and number_of_channels > 0:
                # Append only new channels (no duplicates)
                self._channels_to_hop += list(
                    set(channels_interested) - set(self._channels_to_hop))

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
            num_of_lines = len(m_output)
            if m_output and num_of_lines > 0:
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

        # clear the _packets_to_send on every run of the
        # sniffed frame
        self._packets_to_send = defaultdict(list)
        channels = [str(ch) for ch in universal.ALL_2G_CHANNELS] + ["*"]
        for extension in self._extensions:
            ext_pkts = extension.get_packet(pkt)
            for channel in channels:
                self._packets_to_send[channel] += ext_pkts[channel]

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

        # continue to find clients until told otherwise
        dot11.sniff(
            iface=self._interface,
            prn=self._process_packet,
            store=0,
            stop_filter=self._stopfilter)

    def _send(self):
        """
        Sending thread. Continously broadcasting packets
        crafted by extensions.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """
        while self._should_continue:
            for pkt in self._packets_to_send[self._current_channel] + \
                    self._packets_to_send["*"]:
                try:
                    if is_deauth_cont or not deauth_extension.is_deauth_frame(pkt):
                        logger.debug("Send pkt with A1:%s A2:%s subtype:%s in channel:%s",
                                     pkt.addr1, pkt.addr2, pkt.subtype,
                                     self._current_channel)
                        self._socket.send(pkt)
                except BaseException:
                    continue
        time.sleep(1)
