#pylint: skip-file
import subprocess
from wifiphisher.common.constants import *

class Fw():

    def __init__(self):
        pass

    def nat(self, internal_interface, external_interface):
        subprocess.call(
            ('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE'
            % (external_interface,)),
            shell=True)

        subprocess.call(
            ('iptables -A FORWARD -i %s -o %s -j ACCEPT'
            % (internal_interface, external_interface)),
            shell=True)

    def clear_rules(self):
        subprocess.call('iptables -F', shell=True)
        subprocess.call('iptables -X', shell=True)
        subprocess.call('iptables -t nat -F', shell=True)
        subprocess.call('iptables -t nat -X', shell=True)

    def redirect_requests_localhost(self):
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s:%s'
             % (NETWORK_GW_IP, PORT)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination %s:%s'
             % (NETWORK_GW_IP, 53)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination %s:%s'
             % (NETWORK_GW_IP, 53)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination %s:%s'
             % (NETWORK_GW_IP, SSL_PORT)),
            shell=True)

    def on_exit(self):
        self.clear_rules()


def run_command(command):
    """
    Run the given command and return status of completion and any
    possible errors

    :param command: The command that should be run
    :type command: list
    :return: A tuple containing completion status followed by an error
        or None
    :rtype: (bool, None or str)
    :Example:

        >>> command = ["ls", "-l"]
        >>> run_command(command)
        (True, None)

        >>> command = ["ls", "---"]
        >>> run_command(command)
        (False, "ls: cannot access ' ---': No such file or directory")

    :raises OSError: In case the command does not exist
    """
    _, error = subprocess.Popen(command, stderr=subprocess.PIPE).communicate()

    return (error and (False, error)) or (True, None)


def clear_rules():
    """
    Clear(reset) all the firewall rules back to default state and
    return a tuple containing completion status followed by the first
    error that occurred or None

    :return: A tuple containing completion status followed by an error
        or None
    :rtype: (bool, None or str)
    :Example:

        >>> clear_rules()
        (True, None)

        >>> clear_rules()
        (False, "SOME ERROR HAPPENED")
    """
    iptables = "iptables"
    commands = [[iptables, "-F"], [iptables, "-X"], [iptables, "-t", "nat", "-F"],
                [iptables, "-t", "nat", "-X"]]

    error = filter(lambda result: result[1], map(run_command, commands))[0]

    return (error[1] and (False, error[1])) or (True, None)
