import os
import importlib
import constants
import threading
import scapy.layers.dot11 as dot11
import scapy.arch.linux as linux

class ExtensionManager():
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

    def __init__(self, interface, shared_data):
        """
        Init the EM object. EM objects should be created 
        when all shared data has been gathered.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param interface: String interface object
        :type interface: String
        :param shared_data: Dictionary object
        :type shared_data: Dictionary
        :return: None
        :rtype: None
        """

        self._extensions = []
        self._interface = interface
        self._should_continue = True
        self._socket = linux.L2Socket(iface=self._interface)
        self._packets_to_send = [] 
        # Initialize all extensions with the shared data
        for m in constants.EXTENSIONS:
            mod = importlib.import_module("wifiphisher.extensions." + m)
            Class = getattr(mod, m.title())
            obj = Class(shared_data)
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
        listen_thread = threading.Thread(target=self._listen)
        listen_thread.start()
        # ...another daemon is sending packets
        send_thread = threading.Thread(
            target=self._send)
        send_thread.start()

    def on_exit(self):
        """
        Stops both daemons of EM on exit.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :return: None
        :rtype: None
        """

        self._should_continue = False

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
        for m in self._extensions:
            m_output = m.send_output()
            if m_output and len(m_output) > 0:
                output += m_output
        return output

    def _process_packet(self, pkt):
        """
        Gets the output of each extension.
        Merges the outp outputs in a list and returns it.

        :param self: An ExtensionManager object
        :type self: ExtensionManager
        :param pkt: A Scapy packet object
        :type pkt: Scapy Packet
        :return: None
        :rtype: None
        """

        for m in self._extensions:
            received_packets = m.get_packet(pkt)
            if received_packets and len(received_packets) > 0:
                self._packets_to_send += received_packets

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
        while self._should_continue:
            dot11.sniff(iface=self._interface, prn=self._process_packet,
                        count=1, store=0)

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
            if len(self._packets_to_send) > 0:
                while self._should_continue:
                    for pkt in self._packets_to_send:
                        self._socket.send(pkt)
