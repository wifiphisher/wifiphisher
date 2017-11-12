import subprocess
import wifiphisher.common.constants as constants


def run_command(command):
    """
    Run the given command and return status of completion and any
    possible errors

    :param command: The command that should be run
    :type command: list
    :return: A namedtuple containing completion status followed by an error
        or None
    :rtype: namedtuple(status=bool, error_message=None or str)
    :raises OSError: In case the command does not exist
    :Example:

        >>> command = ["ls", "-l"]
        >>> run_command(command)
        Result(status=True, error_message=None)

        >>> command = ["ls", "---"]
        >>> run_command(command)
        Result(status=False, error_message="ls: cannot access ' ---'")
    """
    _, error = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    return ((error and constants.RESULT(False, error))
            or constants.RESULT_NO_ERROR)


def clear_rules():
    """
    Clear(reset) all the firewall rules back to default state and
    return a tuple containing completion status followed by the first
    error that occurred or None

    :return: A tuple containing completion status followed by an error
        or None
    :rtype: namedtuple(status=bool, error_message=None or str)
    :Example:

        >>> clear_rules()
        Result(status=True, error_message=None)

        >>> clear_rules()
        Result(status=False, error_message="SOME ERROR HAPPENED")
    """
    base0 = "iptables -{}"
    base1 = "iptables -t nat -{}"
    commands = [
        base0.format("F").split(),
        base0.format("X").split(),
        base1.format("F").split(),
        base1.format("X").split()
    ]

    error = filter(lambda result: result[1], map(run_command, commands))

    return (len(error) > 1 and error[0]) or constants.RESULT_NO_ERROR


def redirect_to_localhost():
    """
    Configure firewall such that all request are redirected to local
    host

    :return: A namedtuple containing completion status followed by an error
        or None
    :rtype: Result(status=bool, error_message=None or str)
    :Example:

        >>> redirect_to_localhost()
        Result(status=True, error_message=None)

        >>> redirect_to_localhost()
        Result(status=False, error_message="SOME ERROR HAPPNED")
    """
    base = "iptables -t nat -A PREROUTING -p {} --dport {} -j DNAT --to-destination {}:{}"
    commands = [
        base.format("tcp", 80, constants.NETWORK_GW_IP,
                    constants.PORT).split(),
        base.format("tcp", 53, constants.NETWORK_GW_IP, 53).split(),
        base.format("tcp", constants.SSL_PORT, constants.NETWORK_GW_IP,
                    constants.SSL_PORT).split(),
        base.format("udp", 53, constants.NETWORK_GW_IP, 53).split(),
        "sysctl -w net.ipv4.conf.all.route_localnet=1".split()
    ]

    error = filter(lambda result: result[1], map(run_command, commands))

    return (len(error) > 1 and error[0]) or constants.RESULT_NO_ERROR


def enable_internet(in_interface, out_interface):
    """
    Enable internet by forwarding connection to out_interface

    :param in_interface: Name of an interface for input
    :param out_interface: Name of an interface for output
    :type in_interface: str
    :type out_interface: str
    :return: A namedtuple containing completion status followed by an error
        or None
    :rtype: Result(status=bool, error_message=None or str)
    :Example:

        >>> enable_internet("wlan0", "eth0")
        Result(True, None)

        >>> enable_internet("wlan1", "wlan2")
        Result(False, "SOME ERROR HAPPENED")
    """
    commands = [
        "iptables -t nat -A POSTROUTING -o {} -j MASQUERADE".format(
            out_interface).split(),
        "iptables -A FORWARD -i {} -o {} -j ACCEPT".format(
            in_interface,
            out_interface).split(), "sysctl -w net.ipv4.ip_forward=1".split()
    ]

    error = filter(lambda result: result[1], map(run_command, commands))

    return (len(error) > 1 and error[0]) or constants.RESULT_NO_ERROR
