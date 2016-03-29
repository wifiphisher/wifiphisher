""" This module tests all the functions in the phishingpage module. """

import unittest
import sys
import os

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(os.path.join(dir_of_executable, '..'))
sys.path.insert(0, path_to_project_root)

import wifiphisher.phishingpage as phishingpage
from wifiphisher.constants import *


class TestPhishingTemplate(unittest.TestCase):
    """ Tests PhishingTemplate class. """

    def setUp(self):
        """ Sets up the variables for tests. """

        # setup name, description and data
        display_name = "Test"
        description = ("Test Description.")
        self._template = phishingpage.PhishingTemplate("Test", display_name,
                                                       description)

    def test_get_display_name(self):
        """ Tests get_display_name method. """

        self.assertEqual(self._template.get_display_name(),
                         "Test", "Failed to get the name of the template!")

    def test_str(self):
        """ Tests __str__ method. """

        expected = "Test\n\tTest Description.\n"

        self.assertEqual(self._template.__str__(), expected,
                         "Failed to get proper __str__ string!")

    def test_get_description(self):
        """ Tests get_description method. """

        expected = "Test Description."

        self.assertEqual(self._template.get_description(), expected,
                         "Failed to get the correct description!")

    def test_get_path(self):
        """ Test get_path method. """

        expected = PHISHING_PAGES_DIR + "test"

        self.assertEqual(self._template.get_path(), expected,
                         "Failed to get the correct path!")


class TestTemplateManager(unittest.TestCase):
    """ Test TemplateManager class. """

    def setUp(self):
        """ Sets up the variables for tests. """

        self._manager = phishingpage.TemplateManager()
        self._template_path = PHISHING_PAGES_DIR

    def test_get_templates(self):
        """ Tests get_templates method. """

        actual = self._manager.get_templates()

        if ("connection_reset" and "office365" and
                "firmware-upgrade") not in actual:
            self.fail("Failed to get correct templates!")

    def test_find_user_templates(self):
        """ Tests find_user_templates method. """

        name = "new_template"
        path = self._template_path + name

        # create a new directory
        os.makedirs(path)

        actual = self._manager.find_user_templates()

        if name not in actual:
            self.fail("Failed to find a new template!")

        # remove the directory
        os.rmdir(path)

    def test_add_user_templates(self):
        """ Tests add_user_templates method. """

        name = "new_template"
        path = self._template_path + name

        # create a new directory
        os.makedirs(path)

        self._manager.add_user_templates()

        templates = self._manager.get_templates()

        if name not in templates:
            self.fail("Failed to add a new template!")

        # remove the directory
        os.rmdir(path)

if __name__ == '__main__':
    unittest.main()
