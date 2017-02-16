#pylint: skip-file
import subprocess
from constants import *

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
