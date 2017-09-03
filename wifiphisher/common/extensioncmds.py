"""
Define commands sent from extension modules
"""
import Queue

# define the extension command queue in the moudle level
EXTENSION_CMD_QUEUE = Queue.Queue()


class Command(object):
    """
    Interface for the commands
    """

    def execute(self, extension_manager):
        """
        Execute the command
        :param self: A Command object
        :param extension_manager: An ExtensionManager object
        :type self: Command
        :type extension_manager: ExtensionManager
        :return: None
        :rtype: None
        ..note: raise NotImplementedError if the subclass doesn't overwrite
        this method
        """
        raise NotImplementedError()

    def name(self):
        """
        The name of the command
        :param self: A Command object
        :type self: Command
        :return: None
        :rtype: None
        ..note: raise NotImplementedError if the subclass doesn't overwrite
        this method
        """

        raise NotImplementedError()


class BssidChannelUpdateCommand(Command):
    """
    Update the pkts_to_sends as the channel of the particular
    BSSID changes
    """

    def __init__(self, bssid, old_channel, current_channel):
        """
        Construct the class
        :param self: A BssidChannelUpdateCommand object
        :param bssid: The target BSSID
        :param old_channel: The previous channel
        :param current_channel: The new channel
        :type self: BssidChannelUpdateCommand
        :type bssid: str
        :type old_channel: str
        :type current_channel: str
        :return: None
        :rtype:None
        """
        self.bssid = bssid
        self.old_channel = old_channel
        self.current_channel = current_channel

    def execute(self, extension_manager):
        """
        Update the pkt_to_send defined in extension manager
        :param self: A BssidChannelUpdateCommand object
        :param extension_manager: An ExtensionManager object
        :type self: BssidChannelUpdateCommand
        :type extension_manager: ExtensionManager
        :return: None
        :rtype: None
        """

        # clear the deauth/disassociated frames in old channel
        extension_manager.clear_deauth_frames(self.old_channel, self.bssid)

    def name(self):
        """
        Return the name of this command
        """

        return "BssidChannelUpdateCommand"
