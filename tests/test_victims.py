"""This module tests the victims class."""

import os
import sys
import unittest

import wifiphisher.common.victim as victim

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(os.path.join(dir_of_executable, '..'))
sys.path.insert(0, path_to_project_root)
os.chdir(path_to_project_root)


class TestVictim(unittest.TestCase):
    """Tests victim class."""

    def test_victims_inserted_to_dic_and_vendor(self):
        """Create two victims and check if their attributes are correct."""
        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("68:CC:6E:23:44:53", "10.0.0.5")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("68:CC:6E:23:44:53")

        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("5C:BA:37:23:44:53", "10.0.0.6")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("5C:BA:37:23:44:53")

        victims_instance = victim.Victims.get_instance()
        self.assertTrue("68:CC:6E:23:44:53" in victims_instance.victims_dic)
        self.assertTrue("10.0.0.5" == victims_instance.victims_dic["68:CC:6E:23:44:53"].ip_address)
        self.assertTrue("5C:BA:37:23:44:53" in victims_instance.victims_dic)
        self.assertTrue("10.0.0.6" == victims_instance.victims_dic["5C:BA:37:23:44:53"].ip_address)

        # Check if the vendors match correctly
        self.assertTrue("Huawei Technologies" == victims_instance.victims_dic["68:CC:6E:23:44:53"].vendor)
        self.assertTrue("Microsoft" == victims_instance.victims_dic["5C:BA:37:23:44:53"].vendor)

    def test_victim_changed_ipaddr(self):
        """Create and insert a new victim and then change its IP address,"""
        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("5C:BA:37:23:44:53", "10.0.0.6")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("5C:BA:37:23:44:53")

        victims_instance = victim.Victims.get_instance()
        existing_victim = victims_instance.victims_dic["5C:BA:37:23:44:53"]
        existing_victim.assign_ip_to_victim("5C:BA:37:23:44:53", "10.0.0.10")
        self.assertTrue("10.0.0.10" == victims_instance.victims_dic["5C:BA:37:23:44:53"].ip_address)

    def test_os_of_victims(self):
        """Create three victims, checks os against urls."""
        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("68:CC:6E:23:44:53", "10.0.0.5")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("68:CC:6E:23:44:53")

        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("68:CC:6E:23:44:33", "10.0.0.3")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("68:CC:6E:23:44:33")

        victims_instance = victim.Victims.get_instance()
        new_victim = victim.Victim("5C:BA:37:23:44:53", "10.0.0.6")
        victims_instance.add_to_victim_dic(new_victim)
        new_victim.associate_victim_mac_to_vendor("5C:BA:37:23:44:53")

        victims_instance = victim.Victims.get_instance()
        victims_instance.associate_victim_ip_to_os(
            "10.0.0.5",
            "http://connectivitycheck.android.com/generate_204/gener/plox/")

        victims_instance = victim.Victims.get_instance()
        victims_instance.associate_victim_ip_to_os(
            "10.0.0.3",
            "http://gstatic.com/generate_204/")

        victims_instance = victim.Victims.get_instance()
        victims_instance.associate_victim_ip_to_os(
            "10.0.0.6",
            "http://msftncsi.com/lalala/loulou/sasasas.php")

        victims_instance = victim.Victims.get_instance()
        self.assertTrue("Windows" == victims_instance.victims_dic["5C:BA:37:23:44:53"].os)
        self.assertTrue("Android" == victims_instance.victims_dic["68:CC:6E:23:44:53"].os)

if __name__ == '__main__':
    unittest.main()
